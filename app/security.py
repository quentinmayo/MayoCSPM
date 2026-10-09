import hashlib
import os
import re
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from sqlalchemy import select, update

from app.db import Credential, LoginWindow, Member, User, now

passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
ROLES = {"owner": 3, "admin": 2, "analyst": 1, "viewer": 0}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def email(value):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("A valid email address is required")
    return value


def strong_password(value):
    if not 14 <= len(value) <= 256:
        raise ValueError("Use a password between 14 and 256 characters")
    return value


def issue(db, user_id, kind="session", workspace_id=None, name="Browser"):
    token = "mc_" + secrets.token_urlsafe(32)
    row = Credential(user_id=user_id, workspace_id=workspace_id, kind=kind, name=name, digest=digest(token),
                     expires=now() + (timedelta(hours=12) if kind == "session" else timedelta(days=90)))
    db.add(row)
    db.flush()
    return token, row


def authenticate(request: Request, db):
    auth = request.headers.get("authorization", "")
    bearer = auth.startswith("Bearer ")
    token = auth[7:] if bearer else request.cookies.get("mayocspm_session", "")
    row = db.scalar(select(Credential).where(Credential.digest == digest(token), Credential.revoked.is_(False)))
    if not row or row.expires <= now():
        raise HTTPException(401, "Sign in or provide a valid API key")
    if not bearer and request.method not in ("GET", "HEAD", "OPTIONS"):
        require_origin(request)
    return db.get(User, row.user_id), row


def require_origin(request):
    expected = os.getenv("PUBLIC_URL", "http://localhost:8010").rstrip("/")
    if request.headers.get("origin", "").rstrip("/") != expected:
        raise HTTPException(403, "Same-origin browser request required")


def access(request, db, workspace_id, minimum="viewer"):
    user, credential = authenticate(request, db)
    if credential.workspace_id is not None and credential.workspace_id != workspace_id:
        raise HTTPException(403, "API key belongs to another workspace")
    membership = db.scalar(select(Member).where(Member.workspace_id == workspace_id, Member.user_id == user.id))
    if not membership:
        raise HTTPException(404, "Workspace not found")
    if ROLES[membership.role] < ROLES[minimum]:
        raise HTTPException(403, "Insufficient workspace role")
    return user, membership


def verify_password(encoded, value):
    try:
        return passwords.verify(encoded, value)
    except (VerificationError, ValueError):
        return False


def login_limit(request, db, identity):
    # Socket peer only: arbitrary forwarded headers cannot bypass this window.
    peer = request.client.host if request.client else "unknown"
    keys = [digest("peer:" + peer), digest("email:" + identity)]
    for key in keys:
        row = db.get(LoginWindow, key)
        if row and row.started > now() - timedelta(minutes=15):
            if row.attempts >= 20:
                raise HTTPException(429, "Too many attempts; retry after 15 minutes")
            db.execute(update(LoginWindow).where(LoginWindow.key == key).values(attempts=LoginWindow.attempts + 1))
        elif row:
            row.started, row.attempts = now(), 1
        else:
            db.add(LoginWindow(key=key, attempts=1))
    db.commit()


def cipher():
    key = os.getenv("ENCRYPTION_KEY", "")
    if not key:
        raise ValueError("Configure ENCRYPTION_KEY before adding a GitHub token")
    return Fernet(key.encode())


def encrypt(value):
    return cipher().encrypt(value.encode()).decode() if value else None


def decrypt(value):
    return cipher().decrypt(value.encode()).decode() if value else None


def github_repo(value):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", value) or ".." in value:
        raise ValueError("Use an owner/repository name on github.com")
    return value
