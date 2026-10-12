import hashlib
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from app.checks import evaluate
from app.db import Audit, Connection, Credential, Finding, Job, LoginWindow, Resource, now


def audit(db, workspace_id, actor, action, detail=None):
    db.add(Audit(workspace_id=workspace_id, actor=actor, action=action, detail=detail or {}))


def current_resources(db, workspace_id):
    return select(Resource).join(Connection, Connection.id == Resource.connection_id).where(
        Resource.workspace_id == workspace_id, Connection.workspace_id == workspace_id,
        Resource.job_id == Connection.latest_job_id)


def effective_status(finding):
    if finding.status == "accepted" and (not finding.accepted_until or finding.accepted_until <= now()):
        return "open"
    return finding.status


def fingerprint(connection_id, uid, check_id):
    return hashlib.sha256(f"{connection_id}|{uid}|{check_id}".encode()).hexdigest()


def save_snapshot(db, job, snapshot):
    connection = db.scalar(select(Connection).where(Connection.id == job.connection_id,
                                                     Connection.workspace_id == job.workspace_id).with_for_update())
    if not connection:
        raise ValueError("Connection no longer exists")
    if len(snapshot.resources) > 5000 or len(snapshot.observations) > 1000:
        raise ValueError("Snapshot budget exceeded")
    db.execute(delete(Resource).where(Resource.connection_id == connection.id, Resource.workspace_id == job.workspace_id))
    outcomes = []
    seen = set()
    for item in snapshot.resources:
        if item["uid"] in seen:
            continue
        seen.add(item["uid"])
        db.add(Resource(workspace_id=job.workspace_id, connection_id=connection.id, job_id=job.id, **item))
        outcomes.extend({**result, "resource_uid": item["uid"]} for result in evaluate(item))
    outcomes += snapshot.observations
    existing = {f.fingerprint: f for f in db.scalars(select(Finding).where(Finding.workspace_id == job.workspace_id,
                                                                         Finding.connection_id == connection.id))}
    for result in outcomes:
        key = fingerprint(connection.id, result["resource_uid"], result["check_id"])
        finding = existing.get(key)
        if result["status"] == "pass":
            if finding:
                finding.status, finding.last_seen = "resolved", now()
                finding.accepted_until, finding.acceptance_reason = None, None
            continue
        if result["status"] == "unknown":
            continue  # Absence of evidence never resolves an existing failure.
        values = {k: result[k] for k in ("resource_uid", "check_id", "title", "severity", "score", "reasons",
                                         "evidence", "remediation", "reference")}
        if not finding:
            finding = Finding(workspace_id=job.workspace_id, connection_id=connection.id, fingerprint=key, **values)
            db.add(finding)
            existing[key] = finding
        else:
            for key, value in values.items():
                setattr(finding, key, value)
            finding.last_seen = now()
            if effective_status(finding) != "accepted":
                finding.status = "open"
    db.flush()
    if db.scalar(select(func.count()).select_from(Finding).where(Finding.workspace_id == job.workspace_id)) > 50000:
        raise ValueError("Workspace finding budget exceeded; export and review retention")
    connection.latest_job_id = job.id
    job.status = "completed" if all(c["status"] == "complete" for c in snapshot.coverage) else "partial"
    job.resource_count = len(seen)
    job.coverage = snapshot.coverage
    job.assessment = {"pass": sum(x["status"] == "pass" for x in outcomes),
                      "fail": sum(x["status"] == "fail" for x in outcomes),
                      "unknown": sum(x["status"] == "unknown" for x in outcomes), "api_calls": snapshot.api_calls}
    job.finished = now()
    audit(db, job.workspace_id, "worker", "scan.finished", {"job_id": job.id, "status": job.status,
                                                           "resources": job.resource_count})


def enqueue(db, connection, action="scan"):
    existing = db.scalar(select(Job).where(Job.connection_id == connection.id, Job.status.in_(["queued", "running"])))
    if existing:
        return existing
    row = Job(workspace_id=connection.workspace_id, connection_id=connection.id, action=action)
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        row = db.scalar(select(Job).where(Job.connection_id == connection.id, Job.status.in_(["queued", "running"])))
        if not row:
            raise
    return row


def prune(db):
    # Only resolved findings expire. Old open findings remain until explicitly resolved.
    db.execute(delete(Finding).where(Finding.status == "resolved", Finding.last_seen < now() - timedelta(days=90)))
    db.execute(delete(Audit).where(Audit.created < now() - timedelta(days=30)))
    db.execute(delete(Credential).where(Credential.expires < now()))
    db.execute(delete(LoginWindow).where(LoginWindow.started < now() - timedelta(days=1)))
    # Jobs referenced by current snapshots stay; terminal history is bounded to 50 per connection.
    for connection in db.scalars(select(Connection)):
        jobs = list(db.scalars(select(Job.id).where(Job.connection_id == connection.id,
                                                   Job.status.in_(["completed", "partial", "failed"]),
                                                   Job.id != (connection.latest_job_id or 0))
                               .order_by(Job.id.desc()).offset(50)))
        if jobs:
            db.execute(delete(Job).where(Job.id.in_(jobs)))
    for workspace_id in db.scalars(select(Audit.workspace_id).distinct()):
        ids = list(db.scalars(select(Audit.id).where(Audit.workspace_id == workspace_id)
                             .order_by(Audit.id.desc()).offset(10000)))
        if ids:
            db.execute(delete(Audit).where(Audit.id.in_(ids)))


def graph(db, workspace_id):
    from app.relationships import load_snapshot, resource_graph

    return resource_graph(load_snapshot(db, workspace_id))
