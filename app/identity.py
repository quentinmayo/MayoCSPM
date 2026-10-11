"""Bounded OIDC sign-in and PKCE-protected native session handoff.

Okta authenticates identities. Existing MayoCSPM memberships authorize requests.
No email-based automatic linking, IdP token persistence, or native client secrets.
"""
import base64
import hashlib
import json
import os
import re
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from app import db as store
from app.db import AuthFlow, Credential, Identity, User, now
from app.security import (
    authenticate,
    decrypt,
    digest,
    email,
    encrypt,
    issue,
    login_limit,
    password_login_enabled,
    password_user,
    require_origin,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["Identity"])
COOKIE = "mayocspm_oidc_flow"
DEFAULT_REDIRECT = "com.quentinmayo.mayocspm://auth"


def database():
    with store.Session() as db:
        yield db


def configuration():
    issuer = os.getenv("OIDC_ISSUER", "").rstrip("/")
    client_id = os.getenv("OIDC_CLIENT_ID", "")
    secret = os.getenv("OIDC_CLIENT_SECRET", "")
    if not any((issuer, client_id, secret)):
        return None
    if not all((issuer, client_id, secret, os.getenv("ENCRYPTION_KEY"))):
        raise ValueError("OIDC requires issuer, client ID, client secret and ENCRYPTION_KEY")
    parsed = urlsplit(issuer)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or len(issuer) > 600):
        raise ValueError("OIDC_ISSUER must be an HTTPS issuer without query or user information")
    public = os.getenv("PUBLIC_URL", "").rstrip("/")
    origin = urlsplit(public)
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path or origin.query or origin.fragment):
        raise ValueError("OIDC requires an exact HTTPS PUBLIC_URL origin")
    redirect = os.getenv("MOBILE_REDIRECT_URI", DEFAULT_REDIRECT)
    if not re.fullmatch(r"[a-z][a-z0-9+.-]{2,100}://auth", redirect):
        raise ValueError("MOBILE_REDIRECT_URI must be a fixed native application scheme ending in ://auth")
    return {"issuer": issuer, "client_id": client_id, "secret": secret,
            "callback": public + "/api/auth/oidc/callback", "mobile_redirect": redirect}


def validate_configuration():
    if not configuration() and not password_login_enabled():
        raise ValueError("Configure OIDC before disabling password login")


def configured():
    config = configuration()
    if not config:
        raise HTTPException(503, "Okta/OIDC is not configured on this instance")
    return config


def provider_json(url, *, data=None, auth=None):
    # Bound discovery, JWKS and token responses; never follow an endpoint redirect.
    with httpx.Client(timeout=httpx.Timeout(12, connect=3), trust_env=False, follow_redirects=False) as client:
        with client.stream("POST" if data else "GET", url, data=data, auth=auth) as response:
            if response.status_code != 200:
                raise ValueError("Identity provider request failed")
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 65536:
                    raise ValueError("Identity provider response exceeded limit")
                chunks.append(chunk)
    result = json.loads(b"".join(chunks))
    if not isinstance(result, dict):
        raise ValueError("Identity provider response must be an object")
    return result


def discovery(config):
    issuer = config["issuer"]
    metadata = provider_json(issuer + "/.well-known/openid-configuration")
    if metadata.get("issuer") != issuer:
        raise ValueError("Identity provider issuer mismatch")
    expected = urlsplit(issuer)
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint = urlsplit(metadata[name])
        if (endpoint.scheme != "https" or endpoint.netloc != expected.netloc or endpoint.username
                or endpoint.password or endpoint.fragment or endpoint.query):
            raise ValueError("Identity endpoints must stay on the configured HTTPS issuer origin")
    return metadata


def new_flow(db, kind, payload, seconds=300):
    db.execute(delete(AuthFlow).where(AuthFlow.expires <= now()))
    if db.scalar(select(func.count()).select_from(AuthFlow)) >= 200:
        raise HTTPException(429, "Sign-in capacity reached; try again shortly")
    token = secrets.token_urlsafe(32)
    db.add(AuthFlow(digest=digest(token), kind=kind, payload=payload, expires=now() + timedelta(seconds=seconds)))
    db.commit()
    return token


def consume(db, token, kind):
    flow = db.scalar(delete(AuthFlow).where(AuthFlow.digest == digest(token), AuthFlow.kind == kind,
                                           AuthFlow.expires > now()).returning(AuthFlow))
    db.commit()
    if not flow:
        raise ValueError("Sign-in request expired or was already used")
    return flow.payload


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def begin(db, config, *, mobile_challenge=None, mobile_state=None, link_user=None, link_session=None):
    metadata = discovery(config)
    verifier, binding = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    payload = {"nonce": secrets.token_urlsafe(32), "binding": digest(binding), "verifier": encrypt(verifier),
               "issuer": config["issuer"], "client_id": config["client_id"], "mobile_challenge": mobile_challenge,
               "mobile_state": mobile_state, "link_user": link_user, "link_session": link_session}
    state = new_flow(db, "oidc", payload)
    url = metadata["authorization_endpoint"] + "?" + urlencode({
        "client_id": config["client_id"], "redirect_uri": config["callback"], "response_type": "code",
        "scope": "openid email profile", "state": state, "nonce": payload["nonce"],
        "code_challenge": challenge(verifier), "code_challenge_method": "S256"})
    return url, binding


def flow_cookie(response, binding):
    response.set_cookie(COOKIE, binding, httponly=True, secure=True, samesite="lax", max_age=300,
                        path="/api/auth/oidc")


def id_claims(config, metadata, token, nonce):
    if not isinstance(token, str) or len(token) > 16384:
        raise ValueError("Invalid identity token")
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("Unsupported identity signing algorithm")
    keys = provider_json(metadata["jwks_uri"]).get("keys", [])
    if not isinstance(keys, list) or not 1 <= len(keys) <= 20:
        raise ValueError("Invalid signing key set")
    matches = [key for key in keys if key.get("kid") == header["kid"] and key.get("kty") == "RSA"
               and key.get("use", "sig") == "sig" and key.get("alg", "RS256") == "RS256"]
    if len(matches) != 1:
        raise ValueError("No unique signing key")
    key = jwt.PyJWK.from_dict(matches[0], algorithm="RS256").key
    if key.key_size < 2048:
        raise ValueError("Identity signing key is too small")
    claims = jwt.decode(token, key, algorithms=["RS256"], audience=config["client_id"], issuer=config["issuer"],
                        leeway=30, options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]})
    if not secrets.compare_digest(claims["nonce"], nonce):
        raise ValueError("Identity nonce mismatch")
    if claims.get("azp", config["client_id"]) != config["client_id"]:
        raise ValueError("Identity authorized party mismatch")
    if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and claims.get("azp") != config["client_id"]:
        raise ValueError("Identity audience requires an authorized party")
    if not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 255:
        raise ValueError("Invalid identity subject")
    return claims


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Password(Input):
    password: str = Field(min_length=1, max_length=256)


class MobileLogin(Password):
    email: str = Field(max_length=254)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        return email(value)


class Exchange(Input):
    code: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    verifier: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$")


def mobile_session(db, user):
    token, credential = issue(db, user.id, kind="mobile", name="Mobile app")
    db.commit()
    return {"token": token, "expires_at": credential.expires.isoformat() + "Z", "email": user.email}


@router.get("/options")
def options():
    config = configuration()
    return {"password_enabled": password_login_enabled(), "oidc_enabled": bool(config), "provider": "Okta",
            "mobile_redirect_uri": config["mobile_redirect"] if config else DEFAULT_REDIRECT}


@router.post("/mobile/login")
def mobile_login(body: MobileLogin, request: Request, db=Depends(database)):
    # This endpoint returns a bearer token, never an ambient browser cookie.
    return mobile_session(db, password_user(request, db, body.email, body.password))


@router.post("/mobile/exchange")
def mobile_exchange(body: Exchange, db=Depends(database)):
    try:
        payload = consume(db, body.code, "handoff")
        if not secrets.compare_digest(challenge(body.verifier), payload["challenge"]):
            raise ValueError("Native proof mismatch")
        user = db.get(User, payload["user_id"])
        if not user:
            raise ValueError("Account no longer exists")
        return mobile_session(db, user)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, "Mobile sign-in failed or expired; start again") from None


@router.get("/oidc/start")
def start(request: Request, code_challenge: str | None = Query(default=None, pattern=r"^[A-Za-z0-9_-]{43}$"),
          state: str | None = Query(default=None, min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"),
          db=Depends(database)):
    config = configured()
    if bool(code_challenge) != bool(state):
        raise HTTPException(422, "Native sign-in requires both a challenge and state")
    try:
        url, binding = begin(db, config, mobile_challenge=code_challenge, mobile_state=state)
    except (ValueError, KeyError, TypeError, httpx.HTTPError):
        raise HTTPException(502, "Identity provider is unavailable or misconfigured") from None
    response = RedirectResponse(url, status_code=303)
    flow_cookie(response, binding)
    return response


@router.get("/oidc/account")
def account(request: Request, db=Depends(database)):
    user, credential = authenticate(request, db)
    if credential.kind not in ("session", "mobile"):
        raise HTTPException(403, "Use a browser or mobile session for account settings")
    config = configuration()
    linked = bool(config and db.scalar(select(Identity).where(Identity.issuer == config["issuer"], Identity.user_id == user.id)))
    return {"enabled": bool(config), "linked": linked, "provider": "Okta", "password_enabled": password_login_enabled()}


@router.post("/oidc/link")
def link(body: Password, request: Request, response: Response, db=Depends(database)):
    user, credential = authenticate(request, db)
    require_origin(request)
    login_limit(request, db, user.email)
    if credential.kind != "session" or not verify_password(user.password, body.password):
        raise HTTPException(403, "Sign in in the browser and confirm your current password")
    config = configured()
    if db.scalar(select(Identity).where(Identity.issuer == config["issuer"], Identity.user_id == user.id)):
        raise HTTPException(409, "An identity is already linked")
    try:
        url, binding = begin(db, config, link_user=user.id, link_session=credential.id)
    except (ValueError, KeyError, TypeError, httpx.HTTPError):
        raise HTTPException(502, "Identity provider is unavailable or misconfigured") from None
    flow_cookie(response, binding)
    return {"url": url}


@router.delete("/oidc/account")
def unlink(body: Password, request: Request, db=Depends(database)):
    user, credential = authenticate(request, db)
    require_origin(request)
    login_limit(request, db, user.email)
    if (credential.kind != "session" or not password_login_enabled()
            or not verify_password(user.password, body.password)):
        raise HTTPException(403, "Password login and password confirmation are required to unlink")
    config = configured()
    db.execute(delete(Identity).where(Identity.issuer == config["issuer"], Identity.user_id == user.id))
    db.commit()
    return {"ok": True}


@router.get("/oidc/callback", include_in_schema=False)
def callback(request: Request, state: str = Query(max_length=128), code: str = Query(default="", max_length=4096),
             error: str | None = Query(default=None, max_length=255), db=Depends(database)):
    try:
        config = configured()
        pending = db.get(AuthFlow, digest(state))
        if not pending or not secrets.compare_digest(digest(request.cookies.get(COOKIE, "")), pending.payload["binding"]):
            raise ValueError("Sign-in browser mismatch")
        payload = consume(db, state, "oidc")
        if error or not code or payload["issuer"] != config["issuer"] or payload["client_id"] != config["client_id"]:
            raise ValueError("Sign-in canceled or configuration changed")
        metadata = discovery(config)
        tokens = provider_json(metadata["token_endpoint"], data={"grant_type": "authorization_code", "code": code,
                               "redirect_uri": config["callback"], "code_verifier": decrypt(payload["verifier"])},
                               auth=httpx.BasicAuth(config["client_id"], config["secret"]))
        claims = id_claims(config, metadata, tokens.get("id_token"), payload["nonce"])
        identity = db.scalar(select(Identity).where(Identity.issuer == config["issuer"], Identity.subject == claims["sub"]))
        if payload["link_user"]:
            user = db.get(User, payload["link_user"])
            session = db.get(Credential, payload["link_session"])
            if (not user or not session or session.revoked or session.expires <= now() or session.user_id != user.id
                    or claims.get("email_verified") is not True or email(claims.get("email", "")) != user.email):
                raise ValueError("Account link confirmation failed")
            if identity and identity.user_id != user.id:
                raise ValueError("Identity already belongs to another account")
            if not identity:
                db.add(Identity(issuer=config["issuer"], subject=claims["sub"], user_id=user.id))
                db.commit()
        else:
            # Never grant an existing owner's permissions solely by matching an email claim.
            if not identity:
                raise ValueError("Identity must be explicitly linked from an existing local account")
            user = db.get(User, identity.user_id)
            if not user:
                raise ValueError("Account no longer exists")
        if payload["mobile_challenge"]:
            handoff = new_flow(db, "handoff", {"user_id": user.id, "challenge": payload["mobile_challenge"]}, seconds=60)
            response = RedirectResponse(config["mobile_redirect"] + "?" + urlencode({"code": handoff, "state": payload["mobile_state"]}), status_code=303)
        else:
            token, _ = issue(db, user.id)
            db.commit()
            response = RedirectResponse("/workspace", status_code=303)
            response.set_cookie("mayocspm_session", token, httponly=True, secure=True, samesite="strict", max_age=43200, path="/")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidToken, httpx.HTTPError, jwt.PyJWTError, IntegrityError):
        db.rollback()
        response = RedirectResponse("/workspace?auth_error=oidc_failed", status_code=303)
    response.delete_cookie(COOKIE, path="/api/auth/oidc", secure=True, httponly=True, samesite="lax")
    return response


@router.post("/sessions/revoke")
def revoke_sessions(request: Request, response: Response, db=Depends(database)):
    user, credential = authenticate(request, db)
    if credential.kind not in ("session", "mobile"):
        raise HTTPException(403, "Use a browser or mobile session to revoke sessions")
    db.execute(update(Credential).where(Credential.user_id == user.id, Credential.kind.in_(["session", "mobile"]))
               .values(revoked=True))
    db.commit()
    response.delete_cookie("mayocspm_session", path="/")
    return {"ok": True}
