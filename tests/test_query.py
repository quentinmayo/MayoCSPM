"""Language semantics, evidence provenance and tenant/cost security boundaries."""

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import Finding, Job, Resource, SavedQuery, now
from app.main import app
from app.query import EXAMPLES, Parser, QueryError, execute
from app.relationships import READ_SLOTS, Snapshot, bounded_graph, context_graph, exposure
from tests.conftest import TestSession


def query(client, workspace, expression):
    response = client.post(f"/api/workspaces/{workspace}/query", json={"expression": expression})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("expression", [example["query"] for example in EXAMPLES])
def test_examples_execute(populated, expression):
    client, workspace, _, _ = populated
    data = query(client, workspace, expression)
    assert data["language"] == "MQL/1" and not data["truncated"]
    ids = {node["id"] for node in data["graph"]["nodes"]}
    assert all(edge["source"] in ids and edge["target"] in ids for edge in data["graph"]["edges"])


def test_join_sort_and_groups(populated):
    client, workspace, _, _ = populated
    data = query(client, workspace, EXAMPLES[1]["query"])
    assert data["rows"]
    assert all(row["r"]["name"] == "customer-api" and row["f"]["status"] == "open" for row in data["rows"])
    counts = query(
        client,
        workspace,
        "MATCH (r:Resource)-[:HAS_FINDING]->(f:Finding) RETURN COUNT(*) AS findings, COUNT(DISTINCT r) AS resources",
    )
    assert counts["rows"] == [{"findings": 7, "resources": 4}]
    by_severity = query(client, workspace, EXAMPLES[6]["query"])
    assert sum(row["findings"] for row in by_severity["rows"]) == 7
    assert [row["findings"] for row in by_severity["rows"]] == sorted(
        [row["findings"] for row in by_severity["rows"]], reverse=True
    )
    assert counts["counts_complete"]


def test_paths_direction_and_depth(populated):
    client, workspace, connection, _ = populated
    result = query(
        client,
        workspace,
        'MATCH p=(i:Internet)-[:PUBLIC_CONFIGURATION|SECURITY_GROUP_ATTACHED|USES_VOLUME*1..3]->(r:Resource) WHERE r.kind = "ec2.volume" RETURN p, r',
    )
    assert {row["p"]["length"] for row in result["rows"]} == {2, 3}
    assert all(row["r"]["name"] == "app-storage" for row in result["rows"])
    assert not query(client, workspace, "MATCH (r:Resource)-[:PUBLIC_CONFIGURATION]->(i:Internet) RETURN r")["rows"]
    assert (
        len(query(client, workspace, "MATCH (r:Resource)<-[:PUBLIC_CONFIGURATION]-(i:Internet) RETURN r")["rows"]) == 3
    )
    assert (
        len(query(client, workspace, "MATCH (r:Resource)-[:PUBLIC_CONFIGURATION]-(i:Internet) RETURN r")["rows"]) == 3
    )
    assert (
        len(query(client, workspace, 'MATCH (r:Resource) WHERE r.kind STARTS WITH "ec2." RETURN r LIMIT 1')["rows"])
        == 1
    )
    context = client.get(
        f"/api/workspaces/{workspace}/graph/context", params={"node_id": f"{connection}:vol-demo-app", "depth": 3}
    ).json()
    assert {p["length"] for p in context["paths"]} == {2, 3}
    assert any(e["type"] == "USES_VOLUME" for e in context["edges"])
    assert all(e["type"] not in ("CONTAINS", "REPORTED") for e in context["edges"])


@pytest.mark.parametrize(
    "filter_,count",
    [
        ("r.data.nonexistent != true", 0),
        ("NOT r.data.nonexistent = true", 0),
        ("r.data.nonexistent NOT IN [true]", 0),
        ("r.data.nonexistent IS NULL", 5),
        ("r.data.nonexistent IS NOT NULL", 0),
        ('r.kind IN ["ec2.instance", null]', 1),
        ('r.kind NOT IN ["ec2.instance", null]', 0),
        ('r.data.tags["environment"] = "production"', 3),
        ('r.name ICONTAINS "CUSTOMER"', 1),
        ('r.name ENDS WITH "api"', 1),
        ('r.data.security_groups CONTAINS "sg-demo-web"', 1),
        ("r.data.size_gib >= 23.5", 1),
        ("r.data.encrypted = 1", 0),
        ("r.data.size_gib < -1", 0),
        ('NOT (r.kind = "s3.bucket" OR r.kind = "ec2.volume")', 3),
    ],
)
def test_unknown_values_and_filters(populated, filter_, count):
    client, workspace, _, _ = populated
    assert len(query(client, workspace, f"MATCH (r:Resource) WHERE {filter_} RETURN r")["rows"]) == count


@pytest.mark.parametrize(
    "expression",
    [
        "SELECT * FROM resources",
        "MATCH (r:Resource) DELETE r RETURN r",
        "MATCH (r:Resource) RETURN r; DROP TABLE users",
        "MATCH (r:Resource), (f:Finding) RETURN r, f",
        "MATCH (r:Resource)-[:USES_VOLUME*1..100]->(x:Resource) RETURN r",
        "MATCH (r:Resource)-[:USES_VOLUME*0..2]->(x:Resource) RETURN r",
        "MATCH (r:Resource)-[:USES_VOLUME]->(r:Resource) RETURN r",
        'MATCH (r:Resource) WHERE r.secret = "x" RETURN r',
        "MATCH (r:Resource)-[:INVENTED]->(x:Resource) RETURN r",
        'MATCH (r:Resource) WHERE r.name =~ ".*" RETURN r',
        "MATCH (r:Resource) WHERE r.name = null RETURN r",
        "MATCH (r:Resource) WHERE r.name = 'x' RETURN r",
        "MATCH (r:Resource) RETURN r LIMIT 201",
        "MATCH (r:Resource) RETURN r ORDER BY other",
        "MATCH (r:Resource) RETURN r, r",
        "MATCH (r:Resource) WHERE " + ("NOT " * 14) + 'r.name = "x" RETURN r',
        "MATCH (r:Resource) WHERE r.name IN [" + ",".join("1" for _ in range(51)) + "] RETURN r",
        "MATCH (r:Resource) RETURN " + ",".join(f"r.name AS c{i}" for i in range(13)),
        "MATCH (r:Resource) RETURN r " + " " * 8192,
    ],
)
def test_invalid_language_rejected(expression):
    with pytest.raises(QueryError):
        Parser(expression).parse()


def test_multiconnection_ids_and_scoping(populated):
    client, workspace, first, _ = populated
    c = client.post(f"/api/workspaces/{workspace}/connections", json={"kind": "demo", "name": "Other account"}).json()
    client.post(f"/api/workspaces/{workspace}/connections/{c['id']}/scan")
    from app.worker import work_once

    assert work_once()
    data = query(client, workspace, "MATCH (g:Resource)-[:SECURITY_GROUP_ATTACHED]->(r:Resource) RETURN g, r")
    assert len(data["rows"]) == 2
    assert all(row["g"]["connection_id"] == row["r"]["connection_id"] for row in data["rows"])
    assert {row["g"]["connection_id"] for row in data["rows"]} == {first, c["id"]}
    other = client.post("/api/workspaces", json={"name": "Empty"}).json()["id"]
    assert query(client, other, "MATCH (r:Resource) RETURN r")["rows"] == []
    assert (
        client.get(f"/api/workspaces/{other}/graph/context", params={"node_id": f"{first}:i-demo-web"}).status_code
        == 404
    )
    key = client.post(f"/api/workspaces/{workspace}/keys", json={"name": "Query CI"}).json()["token"]
    with TestClient(app) as machine:
        machine.headers["Authorization"] = "Bearer " + key
        assert query(machine, workspace, "MATCH (c:Connection) RETURN c")["rows"]
        assert (
            machine.post(
                f"/api/workspaces/{other}/query", json={"expression": "MATCH (r:Resource) RETURN r"}
            ).status_code
            == 403
        )
    assert "secret" not in json.dumps(query(client, workspace, "MATCH (c:Connection) RETURN c")["rows"])


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_saved_queries_roles_origin_and_isolation(populated, role):
    client, workspace, _, _ = populated
    base = f"/api/workspaces/{workspace}"
    body = {"name": "Shared", "expression": "MATCH (r:Resource) RETURN r"}
    saved = client.post(base + "/queries", json=body).json()
    other = client.post("/api/workspaces", json={"name": "Other"}).json()["id"]
    assert client.put(f"/api/workspaces/{other}/queries/{saved['id']}", json=body).status_code == 404
    assert client.delete(f"/api/workspaces/{other}/queries/{saved['id']}").status_code == 404
    client.post(
        base + "/members",
        json={"email": role + "@example.com", "role": role, "password": "query-fixture-password-only"},
    )
    with TestClient(app) as member:
        member.headers["Origin"] = "http://testserver"
        member.post("/api/auth/login", json={"email": role + "@example.com", "password": "query-fixture-password-only"})
        assert len(member.get(base + "/queries").json()) == 1
        assert member.get(base + "/query/schema").status_code == 200
        assert query(member, workspace, body["expression"])["rows"]
        assert (
            member.post(
                base + "/query", headers={"Origin": "https://evil.example"}, json={"expression": body["expression"]}
            ).status_code
            == 403
        )
        assert member.post(f"/api/workspaces/{other}/query", json={"expression": body["expression"]}).status_code == 404
        assert member.get(f"/api/workspaces/{other}/queries").status_code == 404
        assert (member.post(base + "/queries", json={**body, "name": "Another"}).status_code == 201) == (
            role != "viewer"
        )
        assert (member.put(base + f"/queries/{saved['id']}", json={**body, "name": "Renamed"}).status_code == 200) == (
            role != "viewer"
        )
        assert (member.delete(base + f"/queries/{saved['id']}").status_code == 200) == (role != "viewer")


def test_saved_query_caps_validation_and_audit(owner):
    client, workspace = owner
    base = f"/api/workspaces/{workspace}"
    body = {"name": "First", "expression": "MATCH (r:Resource) RETURN r"}
    assert client.post(base + "/queries", json={**body, "expression": "DROP TABLE users"}).status_code == 422
    assert client.post(base + "/queries", json={**body, "name": "   "}).status_code == 422
    assert client.post(base + "/queries", json=body).status_code == 201
    assert client.post(base + "/queries", json=body).status_code == 409
    with TestSession() as db:
        for i in range(49):
            db.add(SavedQuery(workspace_id=workspace, name=f"Saved {i}", expression=body["expression"]))
        db.commit()
    assert client.post(base + "/queries", json={**body, "name": "Overflow"}).status_code == 409
    audit = client.get(base + "/audit").json()
    assert any(a["action"] == "query.created" for a in audit)
    assert all("expression" not in a["detail"] for a in audit)


def test_evidence_provenance_public_s3_and_log_consumers(populated):
    client, workspace, connection, job = populated
    with TestSession() as db:
        db.add(
            Resource(
                workspace_id=workspace,
                connection_id=connection,
                job_id=job,
                uid="aws:example:cloudtrail",
                name="Audit service",
                kind="cloudtrail.account",
                region="global",
                data={"storage_buckets": ["example-demo-reports"]},
            )
        )
        db.commit()
    data = query(client, workspace, EXAMPLES[3]["query"])
    assert data["rows"][0]["t"]["name"] == "Audit service"
    edge = next(e for e in data["graph"]["edges"] if e["type"] == "LOGS_TO")
    assert edge["confidence"] == "observed" and edge["evidence"]["bucket_name"] == "example-demo-reports"
    assert "unverified" in edge["limitations"]
    assert (
        exposure(
            {
                "kind": "s3.bucket",
                "data": {"policy_public": True, "block_public_access": {"RestrictPublicBuckets": True}},
            }
        )[0]
        == "not_observed"
    )
    assert (
        exposure(
            {
                "kind": "s3.bucket",
                "data": {
                    "policy_public": True,
                    "block_public_access": {"BlockPublicPolicy": True, "RestrictPublicBuckets": False},
                },
            }
        )[0]
        == "potential"
    )
    assert exposure({"kind": "s3.bucket", "data": {"policy_public": None}})[0] == "unknown"
    assert (
        exposure(
            {
                "kind": "ec2.security_group",
                "data": {
                    "ingress": [
                        {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 443, "ToPort": 443, "IpProtocol": "tcp"}
                    ]
                },
            }
        )[0]
        == "potential"
    )


def test_metadata_budget_missing_current_and_expired_acceptance(populated, monkeypatch):
    client, workspace, _, _ = populated
    with TestSession() as db:
        resource = db.scalar(select(Resource).where(Resource.kind == "s3.bucket"))
        resource.data = {"policy_public": True, "padding": "x" * 70000}
        finding = db.scalar(select(Finding))
        finding.status = "accepted"
        finding.accepted_until = now() - timedelta(seconds=1)
        db.commit()
    data = query(
        client, workspace, 'MATCH (r:Resource) WHERE r.kind = "s3.bucket" RETURN r.exposure AS exposure, r.data AS data'
    )
    assert data["rows"] == [{"exposure": "unknown", "data": None}] and "metadata_limit" in data["warnings"]
    assert not data["counts_complete"]
    assert query(client, workspace, 'MATCH (f:Finding) WHERE f.status = "open" RETURN COUNT(*) AS count')["rows"] == [
        {"count": 7}
    ]
    monkeypatch.setattr("app.relationships.RESOURCE_LIMIT", 1)
    data = query(client, workspace, "MATCH (f:Finding) WHERE f.resource_current IS NULL RETURN f")
    assert data["rows"] and "resource_limit" in data["warnings"]


def test_execution_and_response_budgets(populated, monkeypatch):
    import app.query as module

    client, workspace, _, _ = populated
    original = module.Budget.tick

    def short_budget(self):
        original(self)
        if self.operations > 7:
            raise module.BudgetExceeded

    monkeypatch.setattr(module.Budget, "tick", short_budget)
    data = query(client, workspace, "MATCH (r:Resource) RETURN r ORDER BY r.name")
    assert data["rows"] and "execution_limit" in data["warnings"]
    assert not data["counts_complete"]
    snapshot = Snapshot(nodes={str(i): {"id": str(i), "name": "x" * 2000, "entity": "Resource"} for i in range(200)})
    for i in range(199):
        snapshot.edge(str(i), str(i + 1), "USES_VOLUME")
    graph = bounded_graph(snapshot, set(snapshot.nodes), snapshot.edges, node_limit=5, byte_limit=12000)
    ids = {n["id"] for n in graph["nodes"]}
    assert len(ids) <= 5 and all(e["source"] in ids and e["target"] in ids for e in graph["edges"])
    assert "result_graph_limit" in snapshot.warnings
    # No slots means immediate overload feedback, never an unbounded work queue.
    assert READ_SLOTS.acquire(False) and READ_SLOTS.acquire(False)
    try:
        assert (
            client.post(
                f"/api/workspaces/{workspace}/query", json={"expression": "MATCH (r:Resource) RETURN r"}
            ).status_code
            == 503
        )
    finally:
        READ_SLOTS.release()
        READ_SLOTS.release()


def test_path_search_stays_bounded():
    snapshot = Snapshot(nodes={"internet": {"id": "internet", "entity": "Internet", "name": "Internet"}})
    for i in range(160):
        snapshot.nodes[str(i)] = {"id": str(i), "entity": "Resource", "name": str(i)}
        snapshot.edge("internet", str(i), "PUBLIC_CONFIGURATION", "candidate")
    for i in range(100):
        for j in range(50):
            snapshot.edge(str(i), str(j + 100), "SECURITY_GROUP_ATTACHED")
    result = context_graph(snapshot, "159", depth=1)
    assert "path_limit" in result["warnings"]
    assert len(result["paths"]) <= 20 and len(result["nodes"]) <= 150 and len(result["edges"]) <= 300


def test_query_never_calls_provider(populated, monkeypatch):
    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **k: pytest.fail("No live AWS calls during queries"))
    client, workspace, _, _ = populated
    assert query(client, workspace, "MATCH (r:Resource) RETURN r")["rows"]
    with TestSession() as db:
        assert execute(db, workspace, 'MATCH (r:Resource) WHERE r.name = "\\" OR 1=1 --" RETURN r')["rows"] == []


def test_group_references_keep_account_evidence_and_unknown_coverage(populated):
    client, workspace, connection, job = populated
    with TestSession() as db:
        group = db.scalar(select(Resource).where(Resource.kind == "ec2.security_group"))
        group.uid = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-demo-web"
        db.add(
            Resource(
                workspace_id=workspace,
                connection_id=connection,
                job_id=job,
                uid="sg-demo-private",
                name="Private service group",
                kind="ec2.security_group",
                region="us-east-1",
                data={"ingress": [{"UserIdGroupPairs": [{"GroupId": "sg-demo-web", "UserId": "111111111111"}]}]},
            )
        )
        db.add(
            Resource(
                workspace_id=workspace,
                connection_id=connection,
                job_id=job,
                uid="sg-demo-cross",
                name="External account group",
                kind="ec2.security_group",
                region="us-east-1",
                data={"ingress": [{"UserIdGroupPairs": [{"GroupId": "sg-demo-web", "UserId": "222222222222"}]}]},
            )
        )
        db.get(Job, job).coverage = [{"service": "s3", "region": "us-east-1", "status": "unknown"}]
        db.commit()
    result = query(client, workspace, "MATCH (a:Resource)-[e:ALLOWS_GROUP]->(b:Resource) RETURN a, b, e")
    assert len(result["rows"]) == 1
    assert result["rows"][0]["b"]["name"] == "Private service group"
    assert result["rows"][0]["e"]["evidence"]["account_id"] == "111111111111"
    assert "collection_gaps" in result["warnings"] and not result["counts_complete"]


def test_large_inventory_admission_is_explicit(populated):
    client, workspace, connection, job = populated
    with TestSession() as db:
        db.add_all(
            Resource(
                workspace_id=workspace,
                connection_id=connection,
                job_id=job,
                uid=f"fixture:{i}",
                kind="ec2.volume",
                name=f"Volume {i}",
                region="us-east-1",
                data={},
            )
            for i in range(1000)
        )
        db.add_all(
            Finding(
                workspace_id=workspace,
                connection_id=connection,
                fingerprint=f"{i:064x}",
                resource_uid=f"fixture:{i % 1000}",
                check_id="fixture",
                title="Synthetic risk",
                severity="low",
                score=1,
                reasons=[],
                evidence={},
                remediation="Review fixture",
                reference="https://example.com",
            )
            for i in range(2000)
        )
        db.commit()
    result = query(client, workspace, "MATCH (r:Resource) RETURN COUNT(*) AS count")
    assert result["rows"] == [{"count": 1000}]
    assert {"resource_limit", "finding_limit"} <= set(result["warnings"])
    assert not result["counts_complete"]
    graph = client.get(f"/api/workspaces/{workspace}/graph").json()
    ids = {n["id"] for n in graph["nodes"]}
    assert graph["truncated"] and len(ids) <= 1001
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])
