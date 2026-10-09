import json
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select

from app.checks import CHECKS
from app.collectors import settings
from app.db import (
    Audit,
    Base,
    Connection,
    Credential,
    Finding,
    Job,
    Member,
    Resource,
    Session,
    User,
    Workspace,
    engine,
    now,
)
from app.github import parse_sarif
from app.security import (
    ROLES,
    access,
    authenticate,
    email,
    encrypt,
    github_repo,
    issue,
    login_limit,
    passwords,
    require_origin,
    strong_password,
    verify_password,
)
from app.service import audit, current_resources, effective_status, enqueue, graph, prune, save_snapshot

STATIC = Path(__file__).parent / "static"


def bootstrap():
    Base.metadata.create_all(engine)
    identity, password = os.getenv("BOOTSTRAP_EMAIL"), os.getenv("BOOTSTRAP_PASSWORD")
    if identity and password:
        with Session() as db:
            if not db.scalar(select(User).where(User.email == email(identity))):
                db.add(User(email=email(identity), password=passwords.hash(strong_password(password))))
                db.commit()


@asynccontextmanager
async def lifespan(_):
    bootstrap()
    yield


app = FastAPI(title="MayoCSPM", version="0.1.0-preview", lifespan=lifespan,
              description="Configuration-only cloud posture API. All cloud operations are read-only.")


@app.exception_handler(RequestValidationError)
async def invalid_request(_, exc):
    # FastAPI's default error includes submitted values, which may be passwords or tokens.
    return JSONResponse({"detail": [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]}
                                    for e in exc.errors()]}, status_code=422)


@app.middleware("http")
async def boundaries(request, call_next):
    size = 0
    chunks = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > 2 * 1024 * 1024:
            return JSONResponse({"detail": "Request exceeds the 2 MiB limit"}, status_code=413)
        chunks.append(chunk)
    request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    # Swagger UI uses its own external assets; the application itself is entirely local.
    if not request.url.path.startswith(("/docs", "/redoc")):
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def database():
    with Session() as db:
        yield db


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        return email(value)


class Named(Input):
    name: str = Field(min_length=1, max_length=120)


class MemberInput(Input):
    email: str = Field(max_length=254)
    role: Literal["admin", "analyst", "viewer"]
    password: str | None = Field(default=None, min_length=14, max_length=256)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        return email(value)


class ConnectionInput(Named):
    kind: Literal["aws", "github", "sarif", "demo"]
    role_arn: str | None = Field(default=None, max_length=600)
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"], min_length=1, max_length=4)
    services: list[str] = Field(default_factory=lambda: ["ec2", "s3", "rds", "iam", "cloudtrail", "eks"], max_length=6)
    max_resources: int = Field(default=1000, ge=1, le=5000)
    max_api_calls: int = Field(default=300, ge=10, le=1000)
    repository: str | None = Field(default=None, max_length=201)
    token: str | None = Field(default=None, max_length=512)


class Schedule(Input):
    interval_hours: int = Field(ge=0, le=168)


class Acceptance(Input):
    days: int = Field(ge=1, le=90)
    reason: str = Field(min_length=10, max_length=1000)


def owned(db, cls, workspace_id, object_id):
    row = db.scalar(select(cls).where(cls.id == object_id, cls.workspace_id == workspace_id))
    if not row:
        raise HTTPException(404, "Resource not found")
    return row


def connection_json(row, administrator=False):
    result = {"id": row.id, "name": row.name, "kind": row.kind, "validated": row.validated,
              "config": row.config, "interval_hours": row.interval_hours, "next_scan": row.next_scan,
              "latest_job_id": row.latest_job_id}
    if administrator:
        result["external_id"] = row.external_id
    return result


def job_json(row):
    return {"id": row.id, "connection_id": row.connection_id, "status": row.status, "action": row.action,
            "created": row.created, "finished": row.finished, "coverage": row.coverage, "error": row.error,
            "resource_count": row.resource_count, "assessment": row.assessment}


def finding_json(row):
    return {"id": row.id, "connection_id": row.connection_id, "resource_uid": row.resource_uid,
            "check_id": row.check_id, "title": row.title, "severity": row.severity, "score": row.score,
            "reasons": row.reasons, "evidence": row.evidence, "remediation": row.remediation, "reference": row.reference,
            "status": effective_status(row), "first_seen": row.first_seen, "last_seen": row.last_seen,
            "accepted_until": row.accepted_until, "acceptance_reason": row.acceptance_reason}


@app.get("/health", include_in_schema=False)
def health(db=Depends(database)):
    db.execute(select(1))
    return {"status": "ok", "version": app.version}


@app.post("/api/auth/login")
def login(body: Login, request: Request, response: Response, db=Depends(database)):
    require_origin(request)
    login_limit(request, db, body.email)
    user = db.scalar(select(User).where(User.email == body.email))
    encoded = user.password if user else passwords.hash("unused-public-timing-placeholder")
    verified = verify_password(encoded, body.password)
    if not user or not verified:
        raise HTTPException(401, "Email or password is incorrect")
    token, _ = issue(db, user.id)
    db.commit()
    response.set_cookie("mayocspm_session", token, httponly=True, secure=os.getenv("PUBLIC_URL", "").startswith("https:"),
                        samesite="strict", max_age=43200, path="/")
    return {"email": user.email}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db=Depends(database)):
    _, credential = authenticate(request, db)
    credential.revoked = True
    db.commit()
    response.delete_cookie("mayocspm_session", path="/")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request, db=Depends(database)):
    user, _ = authenticate(request, db)
    return {"email": user.email, "product": "MayoCSPM", "version": app.version}


@app.get("/api/workspaces")
def workspaces(request: Request, db=Depends(database)):
    user, credential = authenticate(request, db)
    rows = db.execute(select(Workspace, Member.role).join(Member).where(Member.user_id == user.id))
    return [{"id": w.id, "name": w.name, "role": role} for w, role in rows
            if credential.workspace_id is None or credential.workspace_id == w.id]


@app.post("/api/workspaces", status_code=201)
def new_workspace(body: Named, request: Request, db=Depends(database)):
    user, credential = authenticate(request, db)
    if credential.kind != "session":
        raise HTTPException(403, "Sign in to create a workspace")
    if db.scalar(select(func.count()).select_from(Workspace)) >= 100:
        raise HTTPException(409, "Instance workspace budget reached")
    workspace = Workspace(name=body.name.strip())
    db.add(workspace)
    db.flush()
    db.add(Member(workspace_id=workspace.id, user_id=user.id, role="owner"))
    audit(db, workspace.id, user.email, "workspace.created")
    db.commit()
    return {"id": workspace.id, "name": workspace.name, "role": "owner"}


@app.get("/api/workspaces/{workspace_id}/members")
def members(workspace_id: int, request: Request, db=Depends(database)):
    access(request, db, workspace_id, "admin")
    return [{"id": m.id, "email": u.email, "role": m.role} for m, u in db.execute(
        select(Member, User).join(User).where(Member.workspace_id == workspace_id))]


@app.post("/api/workspaces/{workspace_id}/members", status_code=201)
def add_member(workspace_id: int, body: MemberInput, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    if db.scalar(select(func.count()).select_from(Member).where(Member.workspace_id == workspace_id)) >= 100:
        raise HTTPException(409, "Workspace member budget reached")
    user = db.scalar(select(User).where(User.email == body.email))
    if not user:
        if db.scalar(select(func.count()).select_from(User)) >= 1000:
            raise HTTPException(409, "Instance account budget reached")
        if not body.password:
            raise HTTPException(422, "A new member requires a password of at least 14 characters")
        user = User(email=body.email, password=passwords.hash(body.password))
        db.add(user)
        db.flush()
    member = db.scalar(select(Member).where(Member.user_id == user.id, Member.workspace_id == workspace_id))
    if member:
        if member.role == "owner":
            raise HTTPException(409, "Owner role cannot be changed here")
        member.role = body.role
    else:
        member = Member(user_id=user.id, workspace_id=workspace_id, role=body.role)
        db.add(member)
    audit(db, workspace_id, actor.email, "member.assigned", {"email": body.email, "role": body.role})
    db.commit()
    return {"id": member.id, "email": user.email, "role": member.role}


@app.delete("/api/workspaces/{workspace_id}/members/{member_id}")
def remove_member(workspace_id: int, member_id: int, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    row = owned(db, Member, workspace_id, member_id)
    if row.role == "owner":
        raise HTTPException(409, "Workspace owner must remain a member")
    db.delete(row)
    audit(db, workspace_id, actor.email, "member.removed", {"member_id": member_id})
    db.commit()
    return {"ok": True}


@app.get("/api/workspaces/{workspace_id}/connections")
def connections(workspace_id: int, request: Request, db=Depends(database)):
    _, membership = access(request, db, workspace_id)
    return [connection_json(row, ROLES[membership.role] >= 2) for row in db.scalars(
        select(Connection).where(Connection.workspace_id == workspace_id).order_by(Connection.id))]


@app.post("/api/workspaces/{workspace_id}/connections", status_code=201)
def new_connection(workspace_id: int, body: ConnectionInput, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    if db.scalar(select(func.count()).select_from(Connection).where(Connection.workspace_id == workspace_id)) >= 10:
        raise HTTPException(409, "Workspace connection budget is 10")
    config, secret = {}, None
    try:
        if body.kind == "aws":
            if not body.role_arn or not re.fullmatch(r"arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}", body.role_arn):
                raise ValueError("A commercial AWS IAM role ARN is required")
            config = {**settings(body.model_dump()), "role_arn": body.role_arn}
        elif body.kind in ("github", "sarif"):
            config = {"repository": github_repo(body.repository or "")}
            if body.kind == "github":
                if not body.token:
                    raise ValueError("A fine-grained GitHub token is required for alert synchronization")
                secret = encrypt(body.token)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    row = Connection(workspace_id=workspace_id, name=body.name, kind=body.kind, config=config, secret=secret,
                     external_id="mc-" + secrets.token_hex(24), validated=body.kind in ("demo", "sarif"))
    db.add(row)
    db.flush()
    audit(db, workspace_id, actor.email, "connection.created", {"connection_id": row.id, "kind": row.kind})
    db.commit()
    return connection_json(row, True)


@app.post("/api/workspaces/{workspace_id}/connections/{connection_id}/scan", status_code=202)
def scan(workspace_id: int, connection_id: int, request: Request, db=Depends(database)):
    actor, membership = access(request, db, workspace_id, "analyst")
    connection = owned(db, Connection, workspace_id, connection_id)
    if connection.kind == "sarif":
        raise HTTPException(409, "Upload a SARIF report for this connection")
    action = "validate" if not connection.validated else "scan"
    if action == "validate" and ROLES[membership.role] < 2:
        raise HTTPException(403, "Administrator must validate the connection first")
    recent = db.scalar(select(Job).where(Job.connection_id == connection_id, Job.created > now() - timedelta(minutes=5),
                                        Job.status.in_(["completed", "partial", "failed"])))
    if recent:
        raise HTTPException(429, "At most one scan per connection every five minutes")
    row = enqueue(db, connection, action)
    audit(db, workspace_id, actor.email, "scan.queued", {"job_id": row.id})
    db.commit()
    return job_json(row)


@app.put("/api/workspaces/{workspace_id}/connections/{connection_id}/schedule")
def schedule(workspace_id: int, connection_id: int, body: Schedule, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    row = owned(db, Connection, workspace_id, connection_id)
    if row.kind == "sarif" or (body.interval_hours and not row.validated):
        raise HTTPException(409, "Validate a polling connection before scheduling")
    row.interval_hours = body.interval_hours
    row.next_scan = now() + timedelta(hours=body.interval_hours) if body.interval_hours else None
    audit(db, workspace_id, actor.email, "schedule.changed", {"connection_id": row.id, "hours": body.interval_hours})
    db.commit()
    return connection_json(row, True)


@app.post("/api/workspaces/{workspace_id}/connections/{connection_id}/sarif", status_code=201)
async def upload_sarif(workspace_id: int, connection_id: int, request: Request, file: UploadFile, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "analyst")
    connection = owned(db, Connection, workspace_id, connection_id)
    if connection.kind != "sarif":
        raise HTTPException(409, "Create a SARIF connection for report uploads")
    raw = await file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(413, "Report exceeds 2 MiB")
    try:
        snapshot = parse_sarif(connection.config["repository"], json.loads(raw))
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise HTTPException(422, "Invalid SARIF 2.1.0 report or more than 1000 results") from None
    if db.scalar(select(Job).where(Job.connection_id == connection.id, Job.created > now() - timedelta(minutes=5))):
        raise HTTPException(429, "At most one report per connection every five minutes")
    job = Job(workspace_id=workspace_id, connection_id=connection.id, status="running", action="import")
    db.add(job)
    db.flush()
    save_snapshot(db, job, snapshot)
    audit(db, workspace_id, actor.email, "sarif.imported", {"job_id": job.id})
    prune(db)
    db.commit()
    return job_json(job)


@app.get("/api/workspaces/{workspace_id}/resources")
def resources(workspace_id: int, request: Request, kind: str | None = Query(default=None, max_length=40),
              region: str | None = Query(default=None, max_length=32), q: str = Query(default="", max_length=120),
              tag_key: str | None = Query(default=None, max_length=80), tag_value: str | None = Query(default=None, max_length=256),
              offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=200), db=Depends(database)):
    access(request, db, workspace_id)
    query = current_resources(db, workspace_id)
    if kind:
        query = query.where(Resource.kind == kind)
    if region:
        query = query.where(Resource.region == region)
    if q:
        query = query.where(Resource.name.icontains(q, autoescape=True) | Resource.uid.icontains(q, autoescape=True))
    if tag_key:
        value = Resource.data["tags"][tag_key].as_string()
        query = query.where(value == tag_value if tag_value is not None else value.is_not(None))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(Resource.id).offset(offset).limit(limit))
    return {"total": total, "items": [{"id": r.id, "connection_id": r.connection_id, "uid": r.uid, "kind": r.kind,
             "name": r.name, "region": r.region, "data": r.data, "seen": r.seen} for r in rows]}


@app.get("/api/workspaces/{workspace_id}/findings")
def findings(workspace_id: int, request: Request, status: Literal["open", "accepted", "resolved"] | None = None,
             limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0), db=Depends(database)):
    access(request, db, workspace_id)
    query = select(Finding).where(Finding.workspace_id == workspace_id)
    if status == "open":
        query = query.where((Finding.status == "open") | ((Finding.status == "accepted") & (Finding.accepted_until <= now())))
    elif status == "accepted":
        query = query.where(Finding.status == status, Finding.accepted_until > now())
    elif status:
        query = query.where(Finding.status == status)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    return {"total": total, "items": [finding_json(f) for f in db.scalars(query.order_by(Finding.score.desc(), Finding.id)
                                                                       .offset(offset).limit(limit))]}


@app.post("/api/workspaces/{workspace_id}/findings/{finding_id}/accept")
def accept(workspace_id: int, finding_id: int, body: Acceptance, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    row = owned(db, Finding, workspace_id, finding_id)
    if row.status == "resolved":
        raise HTTPException(409, "Finding has already passed its check")
    row.status, row.accepted_until, row.acceptance_reason = "accepted", now() + timedelta(days=body.days), body.reason
    audit(db, workspace_id, actor.email, "finding.accepted", {"finding_id": row.id, "days": body.days, "reason": body.reason})
    db.commit()
    return finding_json(row)


@app.get("/api/workspaces/{workspace_id}/graph")
def relationships(workspace_id: int, request: Request, db=Depends(database)):
    access(request, db, workspace_id)
    return graph(db, workspace_id)


@app.get("/api/workspaces/{workspace_id}/jobs")
def jobs(workspace_id: int, request: Request, db=Depends(database)):
    access(request, db, workspace_id)
    return [job_json(row) for row in db.scalars(select(Job).where(Job.workspace_id == workspace_id)
                                               .order_by(Job.id.desc()).limit(100))]


@app.get("/api/workspaces/{workspace_id}/summary")
def summary(workspace_id: int, request: Request, db=Depends(database)):
    access(request, db, workspace_id)
    inventory = current_resources(db, workspace_id)
    kinds = dict(db.execute(select(Resource.kind, func.count()).where(Resource.id.in_(inventory.with_only_columns(Resource.id)))
                            .group_by(Resource.kind)).all())
    active = select(Finding).where(Finding.workspace_id == workspace_id, (Finding.status == "open") |
                                  ((Finding.status == "accepted") & (Finding.accepted_until <= now())))
    severities = dict(db.execute(select(Finding.severity, func.count()).where(
        Finding.id.in_(active.with_only_columns(Finding.id))).group_by(Finding.severity)).all())
    connections = list(db.scalars(select(Connection).where(Connection.workspace_id == workspace_id)))
    latest = list(db.scalars(select(Job).where(Job.workspace_id == workspace_id,
                                              Job.id.in_([c.latest_job_id for c in connections if c.latest_job_id]))))
    return {"resource_count": sum(kinds.values()), "resource_kinds": kinds, "open_findings": sum(severities.values()),
            "severities": severities, "connection_count": len(connections), "latest_scans": [job_json(j) for j in latest],
            "limits": {"connections": 10, "resources_per_scan": 5000, "api_calls_per_scan": 1000,
                       "graph_nodes": 1000, "minimum_schedule_hours": 1, "request_mib": 2,
                       "findings_per_workspace": 50000, "audit_days": 30, "terminal_jobs_per_connection": 50},
            "synthetic": any(c.kind == "demo" for c in connections)}


@app.get("/api/workspaces/{workspace_id}/audit")
def audit_log(workspace_id: int, request: Request, db=Depends(database)):
    access(request, db, workspace_id, "admin")
    return [{"id": row.id, "actor": row.actor, "action": row.action, "detail": row.detail, "created": row.created}
            for row in db.scalars(select(Audit).where(Audit.workspace_id == workspace_id).order_by(Audit.id.desc()).limit(100))]


@app.get("/api/workspaces/{workspace_id}/keys")
def keys(workspace_id: int, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    return [{"id": c.id, "name": c.name, "expires": c.expires, "revoked": c.revoked} for c in db.scalars(
        select(Credential).where(Credential.user_id == actor.id, Credential.workspace_id == workspace_id,
                                Credential.kind == "api"))]


@app.post("/api/workspaces/{workspace_id}/keys", status_code=201)
def new_key(workspace_id: int, body: Named, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    if db.scalar(select(func.count()).select_from(Credential).where(Credential.workspace_id == workspace_id,
                                                                  Credential.revoked.is_(False))) >= 100:
        raise HTTPException(409, "Workspace API key budget reached")
    if db.scalar(select(func.count()).select_from(Credential).where(Credential.workspace_id == workspace_id)) >= 1000:
        raise HTTPException(409, "Credential history budget reached; expire old keys before creating more")
    token, row = issue(db, actor.id, "api", workspace_id, body.name[:80])
    audit(db, workspace_id, actor.email, "key.created", {"key_id": row.id})
    db.commit()
    return {"id": row.id, "token": token, "expires": row.expires, "notice": "Shown once; store privately"}


@app.delete("/api/workspaces/{workspace_id}/keys/{key_id}")
def revoke_key(workspace_id: int, key_id: int, request: Request, db=Depends(database)):
    actor, _ = access(request, db, workspace_id, "admin")
    row = owned(db, Credential, workspace_id, key_id)
    row.revoked = True
    audit(db, workspace_id, actor.email, "key.revoked", {"key_id": key_id})
    db.commit()
    return {"ok": True}


@app.get("/api/checks")
def checks():
    return [{"id": c.id, "kind": c.kind, "title": c.title, "severity": c.severity, "remediation": c.remediation,
             "reference": c.reference} for c in CHECKS]


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
