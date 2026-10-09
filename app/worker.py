import argparse
import secrets
import threading
import time
from datetime import timedelta

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import or_, select, update

from app.collectors import AWSCollector, assume, demo_snapshot
from app.db import Base, Connection, Job, Session, engine, now
from app.github import collect_github
from app.security import decrypt
from app.service import audit, enqueue, prune, save_snapshot


def claim():
    with Session() as db:
        stale = list(db.scalars(select(Job).where(Job.status == "running", Job.lease_until < now())))
        for job in stale:
            job.status, job.error, job.finished = "failed", "Worker lease expired; queue a fresh scan", now()
        for connection in db.scalars(select(Connection).where(Connection.interval_hours > 0,
                                                              or_(Connection.validated.is_(True), Connection.kind == "demo"),
                                                              Connection.next_scan <= now())):
            enqueue(db, connection)
            connection.next_scan = now() + timedelta(hours=connection.interval_hours)
        db.commit()
        row = db.scalar(select(Job).where(Job.status == "queued").order_by(Job.id).limit(1))
        if not row:
            return None
        lease = secrets.token_hex(24)
        updated = db.execute(update(Job).where(Job.id == row.id, Job.status == "queued").values(
            status="running", lease=lease, lease_until=now() + timedelta(minutes=2)))
        db.commit()
        return (row.id, lease) if updated.rowcount else None


def heartbeat(job_id, lease, stopped):
    while not stopped.wait(20):
        with Session() as db:
            changed = db.execute(update(Job).where(Job.id == job_id, Job.lease == lease, Job.status == "running").values(
                lease_until=now() + timedelta(minutes=2)))
            db.commit()
            if not changed.rowcount:
                return


def work_once():
    claimed = claim()
    if not claimed:
        return False
    job_id, lease = claimed
    stopped = threading.Event()
    thread = threading.Thread(target=heartbeat, args=(job_id, lease, stopped), daemon=True)
    thread.start()
    try:
        with Session() as db:
            job = db.get(Job, job_id)
            connection = db.get(Connection, job.connection_id)
            config, kind, external_id, secret = connection.config, connection.kind, connection.external_id, connection.secret
        validated = False
        if kind == "demo":
            snapshot = demo_snapshot()
        elif kind == "aws":
            session, account = assume(config, external_id, verify_trust=job.action == "validate")
            validated = True
            snapshot = AWSCollector(session, account, config).collect()
        elif kind == "github":
            snapshot = collect_github(config["repository"], decrypt(secret))
            validated = all(x["status"] == "complete" for x in snapshot.coverage)
        else:
            raise ValueError("This connection accepts uploaded reports only")
        with Session() as db:
            job = db.scalar(select(Job).where(Job.id == job_id, Job.lease == lease, Job.status == "running",
                                              Job.lease_until > now()).with_for_update())
            if job:
                if validated:
                    db.get(Connection, job.connection_id).validated = True
                save_snapshot(db, job, snapshot)
                prune(db)
                db.commit()
    except Exception as exc:
        # Do not log exception strings: SDK and HTTP exceptions can contain sensitive material.
        error = exc.response["Error"].get("Code", "AWSClientError") if isinstance(exc, ClientError) else type(exc).__name__
        if isinstance(exc, BotoCoreError):
            error = "AWSConnectionError"
        with Session() as db:
            job = db.scalar(select(Job).where(Job.id == job_id, Job.lease == lease, Job.status == "running"))
            if job:
                job.status, job.error, job.finished = "failed", error[:160], now()
                audit(db, job.workspace_id, "worker", "scan.failed", {"job_id": job_id, "error": job.error})
                db.commit()
    finally:
        stopped.set()
        thread.join(timeout=2)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    Base.metadata.create_all(engine)
    if args.once:
        work_once()
        return
    while True:
        if not work_once():
            time.sleep(3)


if __name__ == "__main__":
    main()
