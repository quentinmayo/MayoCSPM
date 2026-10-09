import os
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import JSON, Boolean, ForeignKey, Index, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now():
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


state = Path(os.getenv("MAYOCSPM_STATE_DIR", "state"))
state.mkdir(parents=True, exist_ok=True, mode=0o700)
url = os.getenv("DATABASE_URL", f"sqlite:///{state / 'mayocspm.db'}")
engine = create_engine(url, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
if url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def sqlite_settings(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")

Session = sessionmaker(engine, expire_on_commit=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password: Mapped[str] = mapped_column(Text)


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))


class Member(Base):
    __tablename__ = "members"
    __table_args__ = (UniqueConstraint("workspace_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(16))


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    workspace_id: Mapped[int | None] = mapped_column(ForeignKey("workspaces.id"), nullable=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(12))
    expires: Mapped[datetime]
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Connection(Base):
    __tablename__ = "connections"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(16))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_id: Mapped[str] = mapped_column(String(80))
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_hours: Mapped[int] = mapped_column(default=0)
    next_scan: Mapped[datetime | None] = mapped_column(nullable=True)
    latest_job_id: Mapped[int | None] = mapped_column(nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    connection_id: Mapped[int] = mapped_column(ForeignKey("connections.id"))
    action: Mapped[str] = mapped_column(String(16), default="scan")
    status: Mapped[str] = mapped_column(String(16), default="queued")
    created: Mapped[datetime] = mapped_column(default=now)
    finished: Mapped[datetime | None] = mapped_column(nullable=True)
    lease: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    coverage: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(String(160), nullable=True)
    resource_count: Mapped[int] = mapped_column(default=0)
    assessment: Mapped[dict] = mapped_column(JSON, default=dict)


Index("one_active_job_per_connection", Job.connection_id, unique=True,
      sqlite_where=Job.status.in_(["queued", "running"]), postgresql_where=Job.status.in_(["queued", "running"]))


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (UniqueConstraint("connection_id", "uid"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    connection_id: Mapped[int] = mapped_column(ForeignKey("connections.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    uid: Mapped[str] = mapped_column(String(1024))
    kind: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(256))
    region: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict] = mapped_column(JSON)
    seen: Mapped[datetime] = mapped_column(default=now)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("workspace_id", "fingerprint"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    connection_id: Mapped[int] = mapped_column(ForeignKey("connections.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    resource_uid: Mapped[str] = mapped_column(String(1024))
    check_id: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16))
    score: Mapped[int]
    reasons: Mapped[list] = mapped_column(JSON)
    evidence: Mapped[dict] = mapped_column(JSON)
    remediation: Mapped[str] = mapped_column(Text)
    reference: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(16), default="open")
    first_seen: Mapped[datetime] = mapped_column(default=now)
    last_seen: Mapped[datetime] = mapped_column(default=now)
    accepted_until: Mapped[datetime | None] = mapped_column(nullable=True)
    acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    actor: Mapped[str] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created: Mapped[datetime] = mapped_column(default=now)


class LoginWindow(Base):
    __tablename__ = "login_windows"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(default=0)
    started: Mapped[datetime] = mapped_column(default=now)
