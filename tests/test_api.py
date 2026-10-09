import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import Credential, Finding, Job, Member, User, now
from app.main import app
from app.security import digest
from tests.conftest import TestSession


def test_auth_required(client):
    assert client.get("/api/workspaces").status_code == 401
    assert client.get("/api/workspaces/1/resources").status_code == 401
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/").status_code == 200


def test_login_csrf_and_secret_error_redaction(client):
    data = {"email": "owner@example.com", "password": "local-fixture-password-only"}
    assert client.post("/api/auth/login", headers={"Origin": "https://evil.example"}, json=data).status_code == 403
    response = client.post("/api/auth/login", json={**data, "unknown": "sensitive-submitted-input"})
    assert response.status_code == 422
    assert "sensitive-submitted-input" not in response.text


def test_cookie_and_origin(owner):
    client, _ = owner
    assert "mayocspm_session" in client.cookies
    response = client.post("/api/workspaces", headers={"Origin": "https://evil.example"}, json={"name": "bad"})
    assert response.status_code == 403
    response = client.post("/api/auth/logout")
    assert response.status_code == 200
    assert client.get("/api/workspaces").status_code == 401


def test_request_budget(client):
    response = client.post("/api/auth/login", content=b"x" * (2 * 1024 * 1024 + 1))
    assert response.status_code == 413


def test_login_rate_limit(client):
    for _ in range(20):
        assert client.post("/api/auth/login", json={"email": "owner@example.com", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "owner@example.com", "password": "wrong"}).status_code == 429


def test_demo_inventory_query_and_graph(populated):
    client, workspace, _, _ = populated
    base = f"/api/workspaces/{workspace}"
    rows = client.get(base + "/resources?kind=ec2.instance&tag_key=environment&tag_value=production").json()
    assert rows["total"] == 1
    assert rows["items"][0]["name"] == "customer-api"
    assert client.get(base + "/resources?q=%25").json()["total"] == 0  # LIKE wildcard escaped
    assert client.get(base + "/resources?limit=201").status_code == 422
    graph = client.get(base + "/graph").json()
    assert any(edge["relation"] == "security group attached" for edge in graph["edges"])
    assert any(edge["confidence"] == "candidate" for edge in graph["edges"])
    assert "not proof" in graph["model"]
    summary = client.get(base + "/summary").json()
    assert summary["resource_count"] == 5 and summary["synthetic"]
    assert summary["open_findings"] > 0


@pytest.mark.parametrize("role,can_scan,can_admin", [("viewer", False, False), ("analyst", True, False), ("admin", True, True)])
def test_access_matrix(populated, role, can_scan, can_admin):
    client, workspace, connection, job = populated
    base = f"/api/workspaces/{workspace}"
    response = client.post(base + "/members", json={"email": f"{role}@example.com", "role": role,
                                                   "password": "role-fixture-password-only"})
    assert response.status_code == 201
    with TestSession() as db:
        db.get(Job, job).created = now() - timedelta(minutes=6)
        db.commit()
    with TestClient(app) as member:
        member.headers["Origin"] = "http://testserver"
        assert member.post("/api/auth/login", json={"email": f"{role}@example.com", "password": "role-fixture-password-only"}).status_code == 200
        for endpoint in ("resources", "findings", "graph", "summary", "jobs", "connections"):
            assert member.get(base + "/" + endpoint).status_code == 200
        assert (member.post(base + f"/connections/{connection}/scan").status_code == 202) == can_scan
        assert (member.post(base + "/keys", json={"name": "CI"}).status_code == 201) == can_admin
        assert (member.post(base + "/connections", json={"name": "Another", "kind": "demo"}).status_code == 201) == can_admin
        assert (member.get(base + "/audit").status_code == 200) == can_admin
        assert (member.get(base + "/members").status_code == 200) == can_admin
        finding = client.get(base + "/findings").json()["items"][0]
        assert (member.post(base + f"/findings/{finding['id']}/accept", json={"days": 1, "reason": "temporary reviewed exception"}).status_code == 200) == can_admin


def test_workspace_and_child_isolation(populated):
    client, workspace, connection, _ = populated
    second = client.post("/api/workspaces", json={"name": "Second"}).json()["id"]
    base = f"/api/workspaces/{second}"
    assert client.get(base + "/resources").json()["total"] == 0
    assert client.post(base + f"/connections/{connection}/scan").status_code == 404
    finding = client.get(f"/api/workspaces/{workspace}/findings").json()["items"][0]
    assert client.post(base + f"/findings/{finding['id']}/accept", json={"days": 1, "reason": "cross workspace attempt"}).status_code == 404
    client.post(f"/api/workspaces/{workspace}/members", json={"email": "other@example.com", "role": "viewer", "password": "other-fixture-password-only"})
    with TestClient(app) as other:
        other.headers["Origin"] = "http://testserver"
        other.post("/api/auth/login", json={"email": "other@example.com", "password": "other-fixture-password-only"})
        for endpoint in ("resources", "findings", "graph", "jobs", "connections"):
            assert other.get(base + "/" + endpoint).status_code == 404


def test_scoped_keys_hashed_and_revocable(owner):
    client, workspace = owner
    key = client.post(f"/api/workspaces/{workspace}/keys", json={"name": "CI"}).json()
    second = client.post("/api/workspaces", json={"name": "Other"}).json()["id"]
    with TestSession() as db:
        row = db.get(Credential, key["id"])
        assert row.digest == digest(key["token"]) and key["token"] not in row.digest
    with TestClient(app) as machine:
        machine.headers["Authorization"] = "Bearer " + key["token"]
        assert machine.get(f"/api/workspaces/{workspace}/resources").status_code == 200
        assert machine.get(f"/api/workspaces/{second}/resources").status_code == 403
        assert len(machine.get("/api/workspaces").json()) == 1
        assert machine.post("/api/workspaces", json={"name": "Escaped"}).status_code == 403
        client.delete(f"/api/workspaces/{workspace}/keys/{key['id']}")
        assert machine.get(f"/api/workspaces/{workspace}/resources").status_code == 401


def test_membership_revocation_also_revokes_key(owner):
    client, workspace = owner
    member = client.post(f"/api/workspaces/{workspace}/members", json={"email": "admin@example.com", "role": "admin", "password": "admin-fixture-password-only"}).json()
    with TestClient(app) as admin:
        admin.headers["Origin"] = "http://testserver"
        admin.post("/api/auth/login", json={"email": "admin@example.com", "password": "admin-fixture-password-only"})
        key = admin.post(f"/api/workspaces/{workspace}/keys", json={"name": "worker"}).json()
        client.delete(f"/api/workspaces/{workspace}/members/{member['id']}")
        assert admin.get(f"/api/workspaces/{workspace}/resources").status_code == 404
        assert admin.get(f"/api/workspaces/{workspace}/resources", headers={"Authorization": "Bearer " + key["token"]}).status_code == 404


def test_risk_acceptance_expires(populated):
    client, workspace, _, _ = populated
    base = f"/api/workspaces/{workspace}"
    finding = client.get(base + "/findings").json()["items"][0]
    response = client.post(base + f"/findings/{finding['id']}/accept", json={"days": 7, "reason": "Reviewed temporary exception"})
    assert response.json()["status"] == "accepted"
    with TestSession() as db:
        db.get(Finding, finding["id"]).accepted_until = now() - timedelta(seconds=1)
        db.commit()
    assert any(f["id"] == finding["id"] for f in client.get(base + "/findings?status=open").json()["items"])
    assert client.get(base + "/findings?status=accepted").json()["total"] == 0


def test_schedules_and_queue_budget(populated):
    client, workspace, connection, _ = populated
    base = f"/api/workspaces/{workspace}/connections/{connection}"
    assert client.post(base + "/scan").status_code == 429
    assert client.put(base + "/schedule", json={"interval_hours": 1}).status_code == 200
    assert client.put(base + "/schedule", json={"interval_hours": 0}).json()["next_scan"] is None
    assert client.put(base + "/schedule", json={"interval_hours": -1}).status_code == 422


def test_connection_secret_not_returned(owner):
    client, workspace = owner
    response = client.post(f"/api/workspaces/{workspace}/connections", json={"name": "Repo", "kind": "github", "repository": "example/repo", "token": "fixture-noncredential-value"})
    assert response.status_code == 201
    assert "fixture-noncredential-value" not in response.text
    assert "secret" not in response.json()
    with TestSession() as db:
        from app.db import Connection
        assert "fixture-noncredential-value" not in db.get(Connection, response.json()["id"]).secret


def test_owner_cannot_be_removed_or_demoted(owner):
    client, workspace = owner
    member = client.get(f"/api/workspaces/{workspace}/members").json()[0]
    assert client.delete(f"/api/workspaces/{workspace}/members/{member['id']}").status_code == 409
    assert client.post(f"/api/workspaces/{workspace}/members", json={"email": member["email"], "role": "viewer"}).status_code == 409
    with TestSession() as db:
        assert db.scalar(select(Member)).role == "owner"
        assert db.scalar(select(User)).email == member["email"]


def test_sarif_import_discards_messages_and_builds_declared_repo_link(populated):
    client, workspace, _, _ = populated
    base = f"/api/workspaces/{workspace}"
    c = client.post(base + "/connections", json={"name": "App", "kind": "sarif", "repository": "example/customer-api"}).json()
    report = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test scanner"}}, "results": [{"ruleId": "example-rule", "level": "error", "message": {"text": "DO-NOT-PERSIST-MATCHED-SECRET"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main.py"}, "region": {"startLine": 10}, "contextRegion": {"snippet": {"text": "DO-NOT-PERSIST-MATCHED-SECRET"}}}}]}]}]}
    response = client.post(base + f"/connections/{c['id']}/sarif", files={"file": ("report.sarif", json.dumps(report), "application/json")})
    assert response.status_code == 201
    findings = client.get(base + "/findings").text
    assert "DO-NOT-PERSIST" not in findings
    graph = client.get(base + "/graph").json()
    assert any(edge["confidence"] == "declared" for edge in graph["edges"])


def test_connection_budget_and_invalid_arns(owner):
    client, workspace = owner
    base = f"/api/workspaces/{workspace}/connections"
    assert client.post(base, json={"kind": "aws", "name": "bad", "role_arn": "http://169.254.169.254"}).status_code == 422
    assert client.post(base, json={"kind": "aws", "name": "bad", "role_arn": "arn:aws:iam::123456789012:role/Test", "regions": ["evil.example"]}).status_code == 422
    for i in range(10):
        assert client.post(base, json={"kind": "demo", "name": str(i)}).status_code == 201
    assert client.post(base, json={"kind": "demo", "name": "overflow"}).status_code == 409
