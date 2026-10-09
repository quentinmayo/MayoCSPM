import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Barrier
from types import SimpleNamespace

import boto3
import httpx
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from sqlalchemy import select

from app.checks import evaluate, public_ingress, risk
from app.collectors import AWSCollector, CollectionLimit, Snapshot, assume, demo_snapshot, settings
from app.db import Connection, Finding, Job, Resource, now
from app.github import collect_github, parse_sarif
from app.service import enqueue, prune, save_snapshot
from app.worker import claim, work_once
from tests.conftest import TestSession


@pytest.mark.parametrize("protocol,low,high,cidr,expected", [
    ("tcp", 22, 22, "0.0.0.0/0", True), ("6", 0, 65535, "::/0", True),
    ("-1", None, None, "0.0.0.0/0", True), ("udp", 22, 22, "0.0.0.0/0", False),
    ("tcp", 22, 22, "10.0.0.0/8", False), ("tcp", 443, 443, "0.0.0.0/0", False),
])
def test_ingress_ipv4_ipv6_protocol_ranges(protocol, low, high, cidr, expected):
    rule = {"IpProtocol": protocol, "FromPort": low, "ToPort": high,
            "IpRanges": [{"CidrIp": cidr}] if ":" not in cidr else [],
            "Ipv6Ranges": [{"CidrIpv6": cidr}] if ":" in cidr else []}
    assert public_ingress([rule], 22) is expected


def test_unknown_field_is_never_pass():
    results = evaluate({"kind": "rds.instance", "data": {}})
    assert len(results) == 4 and all(r["status"] == "unknown" for r in results)


def test_score_explains_context_and_caps():
    score, reasons = risk("critical", {"public": True, "tags": {"environment": "production"}})
    assert score == 100 and len(reasons) == 3


@pytest.mark.parametrize("config", [{"regions": []}, {"regions": ["us-east-1"] * 5}, {"services": ["s3:GetObject"]},
                                    {"max_resources": 5001}, {"max_api_calls": 1001}, {"regions": ["http://localhost"]}])
def test_scope_limits(config):
    with pytest.raises(ValueError):
        settings(config)


def session():
    return boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")


def test_ec2_sdk_pagination_and_no_data_plane_calls():
    s = session()
    client = s.client("ec2")
    with Stubber(client) as stub:
        stub.add_response("describe_security_groups", {"SecurityGroups": [{"GroupId": "sg-test", "GroupName": "first", "IpPermissions": []}], "NextToken": "more"}, {"MaxResults": 100})
        stub.add_response("describe_security_groups", {"SecurityGroups": [{"GroupId": "sg-second", "GroupName": "second", "IpPermissions": []}]}, {"MaxResults": 100, "NextToken": "more"})
        stub.add_response("describe_instances", {"Reservations": []}, {"MaxResults": 100})
        stub.add_response("describe_volumes", {"Volumes": []}, {"MaxResults": 100})
        collector = AWSCollector(s, "123456789012", {"services": ["ec2"]})
        collector.clients[("ec2", "us-east-1")] = client
        result = collector.collect()
        assert len(result.resources) == 2
        assert result.resources[0]["uid"].startswith("arn:aws:ec2:us-east-1:123456789012:")
        assert all(c["status"] == "complete" for c in result.coverage)
        stub.assert_no_pending_responses()


def test_access_denied_is_unknown_and_other_collectors_continue():
    s = session()
    ec2 = s.client("ec2")
    with Stubber(ec2) as stub:
        stub.add_client_error("describe_security_groups", service_error_code="UnauthorizedOperation", expected_params={"MaxResults": 100})
        stub.add_response("describe_instances", {"Reservations": []}, {"MaxResults": 100})
        stub.add_response("describe_volumes", {"Volumes": []}, {"MaxResults": 100})
        collector = AWSCollector(s, "123456789012", {"services": ["ec2"]})
        collector.clients[("ec2", "us-east-1")] = ec2
        result = collector.collect()
        assert result.coverage[0]["status"] == "unknown"
        assert result.coverage[1]["status"] == "complete"


def test_resource_cap_is_partial():
    s = session()
    ec2 = s.client("ec2")
    with Stubber(ec2) as stub:
        stub.add_response("describe_security_groups", {"SecurityGroups": [{"GroupId": "sg-one"}, {"GroupId": "sg-two"}]}, {"MaxResults": 100})
        collector = AWSCollector(s, "123456789012", {"services": ["ec2"], "max_resources": 1})
        collector.clients[("ec2", "us-east-1")] = ec2
        result = collector.collect()
        assert len(result.resources) == 1
        assert any(c["status"] == "limited" for c in result.coverage)


def test_call_and_size_and_time_budgets():
    collector = AWSCollector(session(), "123456789012", {"max_api_calls": 10})
    for _ in range(10):
        collector.budget()
    with pytest.raises(CollectionLimit, match="api_call_limit"):
        collector.budget()
    collector = AWSCollector(session(), "123456789012", {})
    with pytest.raises(CollectionLimit, match="eight_mib"):
        collector.add("s3.bucket", "big", "big", "us-east-1", {"extra": "x" * (8 * 1024 * 1024)})
    collector.started -= 601
    with pytest.raises(CollectionLimit, match="deadline"):
        collector.budget()


def test_s3_combines_account_and_bucket_flags_and_region_filter():
    s = session()
    s3, control = s.client("s3"), s.client("s3control")
    flags = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    with Stubber(s3) as bucket_stub, Stubber(control) as control_stub:
        control_stub.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": flags}, {"AccountId": "123456789012"})
        bucket_stub.add_response("list_buckets", {"Buckets": [{"Name": "example-test"}, {"Name": "other-region"}]}, {"MaxBuckets": 100})
        bucket_stub.add_response("get_bucket_location", {}, {"Bucket": "example-test", "ExpectedBucketOwner": "123456789012"})
        bucket_stub.add_client_error("get_public_access_block", "NoSuchPublicAccessBlockConfiguration", expected_params={"Bucket": "example-test", "ExpectedBucketOwner": "123456789012"})
        bucket_stub.add_response("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}}, {"Bucket": "example-test", "ExpectedBucketOwner": "123456789012"})
        bucket_stub.add_response("get_bucket_versioning", {}, {"Bucket": "example-test", "ExpectedBucketOwner": "123456789012"})
        bucket_stub.add_response("get_bucket_location", {"LocationConstraint": "eu-west-1"}, {"Bucket": "other-region", "ExpectedBucketOwner": "123456789012"})
        collector = AWSCollector(s, "123456789012", {"services": ["s3"]})
        collector.clients.update({("s3", "us-east-1"): s3, ("s3control", "us-east-1"): control})
        result = collector.collect()
        assert len(result.resources) == 1
        data = result.resources[0]["data"]
        assert all(data["block_public_access"].values()) and not data["policy_public"]
        assert data["versioning"] == "Disabled"


def test_missing_and_wrong_external_id_rejected_before_role_accepted(monkeypatch):
    calls = []
    def assume_role(**kwargs):
        calls.append(kwargs)
        if kwargs.get("ExternalId") != "correct":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole")
        return {"Credentials": {"AccessKeyId": "test", "SecretAccessKey": "test", "SessionToken": "test"}}
    sts = SimpleNamespace(assume_role=assume_role, get_caller_identity=lambda: {"Account": "123456789012"})
    fake = SimpleNamespace(client=lambda *args, **kwargs: sts)
    monkeypatch.setattr("app.collectors.boto3.Session", lambda **kwargs: fake)
    _, account = assume({"role_arn": "arn:aws:iam::123456789012:role/Test", "regions": ["us-east-1"]}, "correct", True, fake)
    assert account == "123456789012"
    assert [call.get("ExternalId") for call in calls] == [None, "mayocspm-wrong-correct", "correct"]


def test_bad_external_id_trust_fails_closed():
    sts = SimpleNamespace(assume_role=lambda **kwargs: {})
    fake = SimpleNamespace(client=lambda *args, **kwargs: sts)
    with pytest.raises(ValueError, match="reject both"):
        assume({"role_arn": "arn:aws:iam::123456789012:role/Test", "regions": ["us-east-1"]}, "correct", True, fake)


def test_dedup_unknown_absence_and_passing_resolution(populated):
    _, workspace, connection, job_id = populated
    with TestSession() as db:
        count = len(list(db.scalars(select(Finding))))
        for snapshot in (demo_snapshot(), Snapshot(coverage=[{"status": "unknown"}])):
            job = Job(workspace_id=workspace, connection_id=connection, status="running")
            db.add(job)
            db.flush()
            save_snapshot(db, job, snapshot)
            db.commit()
            assert len(list(db.scalars(select(Finding)))) == count
            assert all(f.status == "open" for f in db.scalars(select(Finding)))
        clean = deepcopy(demo_snapshot())
        clean.resources[0]["data"]["ingress"] = []
        job = Job(workspace_id=workspace, connection_id=connection, status="running")
        db.add(job)
        db.flush()
        save_snapshot(db, job, clean)
        db.commit()
        assert db.scalar(select(Finding).where(Finding.check_id == "MC-EC2-001")).status == "resolved"
        assert len(list(db.scalars(select(Resource)))) == 5


def test_lease_expiry_is_failed_and_queue_deduplicates(owner):
    client, workspace = owner
    connection = client.post(f"/api/workspaces/{workspace}/connections", json={"name": "Demo", "kind": "demo"}).json()["id"]
    with TestSession() as db:
        c = db.get(Connection, connection)
        first = enqueue(db, c)
        assert enqueue(db, c).id == first.id
        db.commit()
    claimed = claim()
    assert claimed
    with TestSession() as db:
        db.get(Job, claimed[0]).lease_until = now() - timedelta(seconds=1)
        db.commit()
    assert claim() is None
    with TestSession() as db:
        assert db.get(Job, claimed[0]).status == "failed"


def test_postgres_concurrent_enqueue_one_active_job(owner):
    client, workspace = owner
    with TestSession() as db:
        if db.bind.dialect.name != "postgresql":
            pytest.skip("Actual PostgreSQL concurrency check")
    connection = client.post(f"/api/workspaces/{workspace}/connections", json={"name": "Concurrent", "kind": "demo"}).json()["id"]
    barrier = Barrier(2)
    def schedule():
        with TestSession() as db:
            row = db.get(Connection, connection)
            barrier.wait(timeout=10)
            job = enqueue(db, row)
            db.commit()
            return job.id
    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(lambda _: schedule(), range(2)))
    assert ids[0] == ids[1]
    with TestSession() as db:
        assert len(list(db.scalars(select(Job).where(Job.connection_id == connection)))) == 1


def test_retention_keeps_open_findings_and_current_snapshot(populated):
    _, workspace, connection, job = populated
    with TestSession() as db:
        finding = db.scalar(select(Finding))
        finding.status, finding.last_seen = "resolved", now() - timedelta(days=91)
        for _ in range(60):
            db.add(Job(workspace_id=workspace, connection_id=connection, status="completed"))
        db.commit()
        prune(db)
        db.commit()
        assert len(list(db.scalars(select(Job)))) == 51
        assert db.get(Job, job) is not None
        assert db.scalar(select(Finding).where(Finding.id == finding.id)) is None
        assert all(f.status == "open" for f in db.scalars(select(Finding)))


def test_worker_does_not_publish_exception_credentials(owner, monkeypatch):
    client, workspace = owner
    c = client.post(f"/api/workspaces/{workspace}/connections", json={"name": "Demo", "kind": "demo"}).json()["id"]
    client.post(f"/api/workspaces/{workspace}/connections/{c}/scan")
    def fail():
        raise RuntimeError("private-value-must-not-appear")
    monkeypatch.setattr("app.worker.demo_snapshot", fail)
    work_once()
    response = client.get(f"/api/workspaces/{workspace}/jobs")
    assert response.json()[0]["status"] == "failed" and "private-value" not in response.text


def test_sarif_size_result_limit_and_relative_paths():
    report = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "demo", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///private/key"}}}]}]}]}
    result = parse_sarif("example/repo", report)
    assert result.observations[0]["evidence"]["path"] == "[non-relative location omitted]"
    report["runs"][0]["results"] *= 1001
    with pytest.raises(ValueError, match="1000"):
        parse_sarif("example/repo", report)
    assert "file:///private/key" not in json.dumps(result.observations)


def test_github_plan_denial_is_unknown_without_false_zero(monkeypatch):
    original = httpx.Client
    def response(request):
        assert request.url.host == "api.github.com"
        if "code-scanning" in request.url.path:
            return httpx.Response(403, json={"message": "unavailable product"})
        return httpx.Response(200, json=[])
    monkeypatch.setattr("app.github.httpx.Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(response)))
    result = collect_github("example/repo", "fixture-only")
    assert result.coverage[0]["status"] == "unknown"
    assert result.coverage[1]["status"] == "complete"
    assert result.resources and result.api_calls == 2


def test_github_alert_and_response_byte_budgets(monkeypatch):
    original = httpx.Client
    def alerts(request):
        return httpx.Response(200, json=[{"number": i, "rule": {"id": "test-rule"},
                                         "most_recent_instance": {"location": {"path": "app.py", "start_line": 3}}}
                                        for i in range(100)])
    monkeypatch.setattr("app.github.httpx.Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(alerts)))
    result = collect_github("example/repo", "fixture-only", max_alerts=7)
    assert len(result.observations) == 7
    assert all(c["status"] == "limited" for c in result.coverage)
    def huge(request):
        return httpx.Response(200, content=b"[" + b" " * (2 * 1024 * 1024) + b"]")
    monkeypatch.setattr("app.github.httpx.Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(huge)))
    result = collect_github("example/repo", "fixture-only")
    assert not result.observations
    assert all(c.get("error") == "response_size_limit" for c in result.coverage)
