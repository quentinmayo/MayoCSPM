import json
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from app import identity
from app.db import AuthFlow, Credential, Identity, Member, User, now
from app.security import digest
from tests.conftest import TestSession


@pytest.fixture
def provider(owner, monkeypatch):
    client, wid = owner
    client.base_url = httpx.URL("https://testserver")
    client.headers["Origin"] = "https://testserver"
    monkeypatch.setenv("PUBLIC_URL", "https://testserver")
    monkeypatch.setenv("OIDC_ISSUER", "https://identity.example/oauth2/default")
    monkeypatch.setenv("OIDC_CLIENT_ID", "fixture-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "fixture-provider-secret")
    monkeypatch.setenv("PASSWORD_LOGIN_ENABLED", "true")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid="fixture-key", use="sig", alg="RS256")
    controls = {"claims": {}, "nonce": "", "key": key, "calls": []}
    issuer = "https://identity.example/oauth2/default"

    def request(url, *, data=None, auth=None):
        controls["calls"].append((url, data))
        if url.endswith("openid-configuration"):
            return {"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                    "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"}
        if url.endswith("/keys"):
            return {"keys": [public]}
        assert auth is not None and data["code_verifier"]
        claims = {"iss": issuer, "aud": "fixture-client", "sub": "fixture-okta-user", "nonce": controls["nonce"],
                  "iat": int(time.time()), "exp": int(time.time()) + 300, "email": "owner@example.com",
                  "email_verified": True, **controls["claims"]}
        return {"id_token": jwt.encode(claims, controls["key"], algorithm="RS256", headers={"kid": "fixture-key"}),
                "access_token": "provider-token-must-not-be-stored"}
    monkeypatch.setattr(identity, "provider_json", request)
    return client, wid, controls


def begin(client, controls, *, link=False, params=None):
    if link:
        r = client.post("/api/auth/oidc/link", json={"password": "local-fixture-password-only"})
        assert r.status_code == 200
        location = r.json()["url"]
    else:
        r = client.get("/api/auth/oidc/start", params=params, follow_redirects=False)
        assert r.status_code == 303
        location = r.headers["location"]
    query = parse_qs(urlsplit(location).query)
    controls["nonce"] = query["nonce"][0]
    assert query["code_challenge_method"] == ["S256"]
    assert "secret" not in location and "token" not in location
    return query["state"][0]


def finish(client, state):
    return client.get("/api/auth/oidc/callback", params={"state": state, "code": "fixture-code"}, follow_redirects=False)


def link_owner(client, controls):
    assert finish(client, begin(client, controls, link=True)).headers["location"] == "/workspace"


def test_disabled_options_and_missing_configuration(client, monkeypatch):
    for key in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(key, raising=False)
    assert client.get("/api/auth/options").json()["oidc_enabled"] is False
    assert client.get("/api/auth/oidc/start").status_code == 503
    monkeypatch.setenv("PASSWORD_LOGIN_ENABLED", "false")
    with pytest.raises(ValueError, match="Configure OIDC"):
        identity.validate_configuration()


def test_explicit_link_then_oidc_sign_in_and_no_provider_token_storage(provider):
    client, wid, controls = provider
    link_owner(client, controls)
    with TestSession() as db:
        assert db.scalar(select(Identity)).user_id == db.scalar(select(User)).id
        assert "provider-token-must-not-be-stored" not in str(list(db.scalars(select(AuthFlow.payload))))
    client.post("/api/auth/logout")
    response = finish(client, begin(client, controls))
    assert response.headers["location"] == "/workspace"
    assert client.get(f"/api/workspaces/{wid}/summary").status_code == 200
    assert "Secure" in response.headers["set-cookie"] and "HttpOnly" in response.headers["set-cookie"]
    assert client.get("/api/auth/oidc/account").json()["linked"] is True


def test_matching_email_never_automatically_links_owner(provider):
    client, _, controls = provider
    client.cookies.clear()
    response = finish(client, begin(client, controls))
    assert response.headers["location"] == "/workspace?auth_error=oidc_failed"
    assert client.get("/api/me").status_code == 401
    with TestSession() as db:
        assert db.scalar(select(Identity)) is None


@pytest.mark.parametrize("claims", [
    {"nonce": "wrong"}, {"aud": "different-client"}, {"iss": "https://another.example"},
    {"exp": int(time.time()) - 90}, {"iat": int(time.time()) + 90}, {"sub": ""},
    {"azp": "different-client"}, {"aud": ["fixture-client", "another"]},
    {"email_verified": False}, {"email": "different@example.com"},
])
def test_invalid_identity_claims_cannot_link(provider, claims):
    client, _, controls = provider
    controls["claims"] = claims
    response = finish(client, begin(client, controls, link=True))
    assert response.headers["location"].endswith("auth_error=oidc_failed")
    with TestSession() as db:
        assert db.scalar(select(Identity)) is None


def test_untrusted_signature_rejected(provider):
    client, _, controls = provider
    controls["key"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert finish(client, begin(client, controls, link=True)).headers["location"].endswith("oidc_failed")


def test_state_cookie_expiry_and_replay(provider):
    client, _, controls = provider
    state = begin(client, controls, link=True)
    binding = client.cookies.get(identity.COOKIE)
    client.cookies.delete(identity.COOKIE)
    assert finish(client, state).headers["location"].endswith("oidc_failed")
    client.cookies.set(identity.COOKIE, binding)
    assert finish(client, state).headers["location"] == "/workspace"
    assert finish(client, state).headers["location"].endswith("oidc_failed")
    state = begin(client, controls)
    with TestSession() as db:
        db.get(AuthFlow, digest(state)).expires = now() - timedelta(seconds=1)
        db.commit()
    assert finish(client, state).headers["location"].endswith("oidc_failed")


def test_link_requires_own_browser_session_password_and_origin(provider):
    client, _, _ = provider
    assert client.post("/api/auth/oidc/link", json={"password": "wrong"}).status_code == 403
    assert client.post("/api/auth/oidc/link", headers={"Origin": "https://evil.example"},
                       json={"password": "local-fixture-password-only"}).status_code == 403


def test_revoked_browser_session_cannot_finish_link(provider):
    client, _, controls = provider
    state = begin(client, controls, link=True)
    client.post("/api/auth/logout")
    assert finish(client, state).headers["location"].endswith("oidc_failed")
    with TestSession() as db:
        assert db.scalar(select(Identity)) is None


def test_mobile_handoff_pkce_single_use_expiry_and_role_membership(provider):
    client, wid, controls = provider
    link_owner(client, controls)
    verifier = "native-proof-" + "a" * 43
    state = begin(client, controls, params={"code_challenge": identity.challenge(verifier), "state": "s" * 43})
    location = finish(client, state).headers["location"]
    assert location.startswith(identity.DEFAULT_REDIRECT + "?")
    params = parse_qs(urlsplit(location).query)
    assert params["state"] == ["s" * 43] and "token" not in params
    client.cookies.clear()
    response = client.post("/api/auth/mobile/exchange", json={"code": params["code"][0], "verifier": verifier})
    assert response.status_code == 200 and "set-cookie" not in response.headers
    token = response.json()["token"]
    headers = {"Authorization": "Bearer " + token}
    assert client.get(f"/api/workspaces/{wid}/summary", headers=headers).status_code == 200
    assert client.post("/api/auth/mobile/exchange", json={"code": params["code"][0], "verifier": verifier}).status_code == 400
    with TestSession() as db:
        credential = db.scalar(select(Credential).where(Credential.digest == digest(token)))
        assert credential.kind == "mobile" and credential.expires < now() + timedelta(hours=13)
        member = db.scalar(select(Member).where(Member.workspace_id == wid))
        member.role = "viewer"
        db.commit()
    assert client.post(f"/api/workspaces/{wid}/connections", headers=headers, json={"name": "Denied", "kind": "demo"}).status_code == 403
    with TestSession() as db:
        db.delete(db.scalar(select(Member).where(Member.workspace_id == wid)))
        db.commit()
    assert client.get(f"/api/workspaces/{wid}/summary", headers=headers).status_code == 404


@pytest.mark.parametrize("expired", [False, True])
def test_mobile_wrong_proof_and_expired_code(provider, expired):
    client, _, controls = provider
    link_owner(client, controls)
    verifier = "v" * 43
    state = begin(client, controls, params={"code_challenge": identity.challenge(verifier), "state": "s" * 43})
    code = parse_qs(urlsplit(finish(client, state).headers["location"]).query)["code"][0]
    if expired:
        with TestSession() as db:
            db.get(AuthFlow, digest(code)).expires = now() - timedelta(seconds=1)
            db.commit()
    response = client.post("/api/auth/mobile/exchange", json={"code": code, "verifier": verifier if expired else "b" * 43})
    assert response.status_code == 400
    assert client.post("/api/auth/mobile/exchange", json={"code": code, "verifier": verifier}).status_code == 400


def test_password_mobile_login_logout_and_password_disable(owner, monkeypatch):
    client, wid = owner
    response = client.post("/api/auth/mobile/login", headers={"Origin": "https://untrusted.example"},
                           json={"email": "owner@example.com", "password": "local-fixture-password-only"})
    assert response.status_code == 200 and "set-cookie" not in response.headers
    token = response.json()["token"]
    client.cookies.clear()
    headers = {"Authorization": "Bearer " + token}
    assert client.get(f"/api/workspaces/{wid}/summary", headers=headers).status_code == 200
    assert client.post("/api/auth/sessions/revoke", headers=headers).status_code == 200
    assert client.get(f"/api/workspaces/{wid}/summary", headers=headers).status_code == 401
    monkeypatch.setenv("PASSWORD_LOGIN_ENABLED", "false")
    body = {"email": "owner@example.com", "password": "local-fixture-password-only"}
    assert client.post("/api/auth/mobile/login", json=body).status_code == 403
    assert client.post("/api/auth/login", json=body).status_code == 403


def test_discovery_cross_origin_endpoint_and_response_bounds(monkeypatch):
    config = {"issuer": "https://identity.example"}
    monkeypatch.setattr(identity, "provider_json", lambda *_args: {
        "issuer": config["issuer"], "authorization_endpoint": "https://evil.example/authorize"})
    with pytest.raises(ValueError, match="configured HTTPS"):
        identity.discovery(config)
    monkeypatch.undo()
    real_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 65537))
    monkeypatch.setattr(identity.httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs))
    with pytest.raises(ValueError, match="exceeded"):
        identity.provider_json("https://identity.example/keys")


def test_provider_errors_redacted_and_cancel_consumed(provider, monkeypatch):
    client, _, controls = provider
    state = begin(client, controls)
    response = client.get("/api/auth/oidc/callback", params={"state": state, "error": "sensitive-provider-error"}, follow_redirects=False)
    assert "sensitive" not in response.text + response.headers["location"]
    assert finish(client, state).headers["location"].endswith("oidc_failed")
    def failure(*_args, **_kwargs):
        raise httpx.ConnectError("sensitive-provider-secret")
    monkeypatch.setattr(identity, "provider_json", failure)
    response = client.get("/api/auth/oidc/start")
    assert response.status_code == 502 and "sensitive-provider-secret" not in response.text


def test_workspace_api_key_cannot_manage_global_identity_or_sessions(owner):
    client, wid = owner
    key = client.post(f"/api/workspaces/{wid}/keys", json={"name": "fixture"}).json()["token"]
    client.cookies.clear()
    headers = {"Authorization": "Bearer " + key}
    assert client.get("/api/auth/oidc/account", headers=headers).status_code == 403
    assert client.post("/api/auth/sessions/revoke", headers=headers).status_code == 403


def test_sso_only_still_accepts_linked_subject_and_prevents_unlink_lockout(provider, monkeypatch):
    client, wid, controls = provider
    link_owner(client, controls)
    monkeypatch.setenv("PASSWORD_LOGIN_ENABLED", "false")
    assert client.get("/api/auth/options").json()["password_enabled"] is False
    assert client.request("DELETE", "/api/auth/oidc/account", json={"password": "local-fixture-password-only"}).status_code == 403
    client.cookies.clear()
    # Email changes cannot transfer a subject binding to a different local user.
    controls["claims"] = {"email": "changed@example.com"}
    assert finish(client, begin(client, controls)).headers["location"] == "/workspace"
    assert client.get(f"/api/workspaces/{wid}/summary").status_code == 200


def test_unlink_blocks_future_sso_and_global_revoke_preserves_scoped_api_key(provider):
    client, wid, controls = provider
    link_owner(client, controls)
    key = client.post(f"/api/workspaces/{wid}/keys", json={"name": "fixture"}).json()["token"]
    mobile = client.post("/api/auth/mobile/login", json={"email": "owner@example.com", "password": "local-fixture-password-only"}).json()["token"]
    assert client.request("DELETE", "/api/auth/oidc/account", json={"password": "local-fixture-password-only"}).status_code == 200
    assert client.get("/api/auth/oidc/account").json()["linked"] is False
    assert finish(client, begin(client, controls)).headers["location"].endswith("oidc_failed")
    assert client.post("/api/auth/sessions/revoke").status_code == 200
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"Authorization": "Bearer " + mobile}).status_code == 401
    assert client.get(f"/api/workspaces/{wid}/summary", headers={"Authorization": "Bearer " + key}).status_code == 200
