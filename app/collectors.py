"""Bounded configuration-only collection; no data-plane reads or cloud writes."""
import json
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

SERVICES = {"ec2", "s3", "rds", "iam", "cloudtrail", "eks"}
REGION = re.compile(r"(?:us|eu|ap|ca|sa|me|af|il|mx)-(?:[a-z]+-)?[a-z]+-\d")
SDK = Config(connect_timeout=3, read_timeout=12, retries={"mode": "standard", "total_max_attempts": 2})


class CollectionLimit(Exception):
    pass


@dataclass
class Snapshot:
    resources: list = field(default_factory=list)
    coverage: list = field(default_factory=list)
    api_calls: int = 0
    observations: list = field(default_factory=list)


def settings(config):
    regions = config.get("regions", ["us-east-1"])
    services = config.get("services", sorted(SERVICES))
    if not isinstance(regions, list) or not 1 <= len(regions) <= 4 or len(set(regions)) != len(regions):
        raise ValueError("Choose one to four distinct AWS regions")
    if not all(isinstance(r, str) and REGION.fullmatch(r) for r in regions):
        raise ValueError("Invalid commercial AWS region")
    if not isinstance(services, list) or not services or not set(services) <= SERVICES:
        raise ValueError("Choose supported metadata collectors")
    resources, calls = int(config.get("max_resources", 1000)), int(config.get("max_api_calls", 300))
    if not 1 <= resources <= 5000 or not 10 <= calls <= 1000:
        raise ValueError("Resource cap must be 1–5000; logical API-call cap must be 10–1000")
    return {"regions": regions, "services": sorted(set(services)), "max_resources": resources, "max_api_calls": calls}


def assume(config, external_id, verify_trust=False, base=None):
    role = config["role_arn"]
    if not re.fullmatch(r"arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}", role):
        raise ValueError("Use a commercial AWS IAM role ARN")
    sts = (base or boto3.Session()).client("sts", region_name=config["regions"][0], config=SDK)
    params = {"RoleArn": role, "RoleSessionName": "MayoCSPMReadOnly", "DurationSeconds": 3600}
    if verify_trust:
        for wrong in (None, "mayocspm-wrong-" + external_id):
            try:
                sts.assume_role(**params, **({"ExternalId": wrong} if wrong else {}))
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "AccessDenied":
                    raise ValueError("External-ID trust test could not be completed") from None
            else:
                raise ValueError("Role trust must reject both missing and incorrect external IDs")
    response = sts.assume_role(**params, ExternalId=external_id)["Credentials"]
    session = boto3.Session(aws_access_key_id=response["AccessKeyId"], aws_secret_access_key=response["SecretAccessKey"],
                            aws_session_token=response["SessionToken"], region_name=config["regions"][0])
    identity = session.client("sts", config=SDK).get_caller_identity()
    if identity["Account"] != role.split(":")[4]:
        raise ValueError("Assumed identity account does not match the requested role")
    return session, identity["Account"]


class AWSCollector:
    def __init__(self, session, account, config):
        self.session, self.account, self.config = session, account, settings(config)
        self.snapshot = Snapshot()
        self.clients = {}
        self.started = time.monotonic()
        self.metadata_bytes = 0

    def client(self, service, region):
        key = (service, region)
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=SDK)
        return self.clients[key]

    def budget(self):
        if time.monotonic() - self.started >= 600:
            raise CollectionLimit("ten_minute_deadline")
        if self.snapshot.api_calls >= self.config["max_api_calls"]:
            raise CollectionLimit("api_call_limit")
        self.snapshot.api_calls += 1

    def call(self, service, region, operation, **kwargs):
        self.budget()
        return getattr(self.client(service, region), operation)(**kwargs)

    def pages(self, service, region, operation, key, **kwargs):
        client = self.client(service, region)
        if not client.can_paginate(operation):
            yield from self.call(service, region, operation, **kwargs).get(key, [])
            return
        iterator = iter(client.get_paginator(operation).paginate(PaginationConfig={"PageSize": 100}, **kwargs))
        # Count a page before requesting it, including an end-of-iteration probe.
        # This deliberately overestimates logical calls rather than overrunning a budget.
        while True:
            self.budget()
            try:
                page = next(iterator)
            except StopIteration:
                break
            yield from page.get(key, [])

    def add(self, kind, uid, name, region, data):
        if len(self.snapshot.resources) >= self.config["max_resources"]:
            raise CollectionLimit("resource_limit")
        if kind.startswith("ec2.") and not uid.startswith("arn:"):
            prefix = {"ec2.instance": "instance", "ec2.volume": "volume", "ec2.security_group": "security-group"}[kind]
            uid = f"arn:aws:ec2:{region}:{self.account}:{prefix}/{uid}"
        self.metadata_bytes += len(json.dumps(data).encode()) + len(uid) + len(name) + 100
        if self.metadata_bytes > 8 * 1024 * 1024:
            raise CollectionLimit("eight_mib_metadata_limit")
        self.snapshot.resources.append({"kind": kind, "uid": uid, "name": name[:256], "region": region, "data": data})

    @contextmanager
    def section(self, service, region, label=None):
        entry = {"service": service, "region": region, "scope": label or service, "status": "complete"}
        self.snapshot.coverage.append(entry)
        try:
            yield
        except ClientError as exc:
            entry.update(status="unknown", error=exc.response["Error"].get("Code", "AWSClientError")[:80])
        except BotoCoreError:
            entry.update(status="unknown", error="AWSConnectionError")
        except CollectionLimit as exc:
            entry.update(status="limited", error=str(exc))
            raise

    def optional(self, service, region, operation, key, absent=None, absent_codes=(), **kwargs):
        try:
            return self.call(service, region, operation, **kwargs).get(key, absent)
        except ClientError as exc:
            code = exc.response["Error"].get("Code", "AWSClientError")
            if code in absent_codes:
                return absent
            self.snapshot.coverage.append({"service": service, "region": region, "scope": operation,
                                           "status": "unknown", "error": code[:80]})
            return None
        except BotoCoreError:
            self.snapshot.coverage.append({"service": service, "region": region, "scope": operation,
                                           "status": "unknown", "error": "AWSConnectionError"})
            return None

    @staticmethod
    def tags(items):
        # Only ownership/context tags, never arbitrary tag values that may contain credentials.
        allow = {"name", "env", "environment", "owner", "team", "repository", "source-repo", "application"}
        return {t["Key"][:80]: t.get("Value", "")[:256] for t in items if t.get("Key", "").lower() in allow}

    def ec2(self, region):
        for operation, key, kind in [("describe_security_groups", "SecurityGroups", "ec2.security_group"),
                                     ("describe_instances", "Reservations", "ec2.instance"),
                                     ("describe_volumes", "Volumes", "ec2.volume")]:
            with self.section("ec2", region, operation):
                for item in self.pages("ec2", region, operation, key):
                    if kind == "ec2.security_group":
                        self.add(kind, item["GroupId"], item.get("GroupName", item["GroupId"]), region,
                                 {"ingress": [{"IpProtocol": rule.get("IpProtocol"), "FromPort": rule.get("FromPort"),
                                               "ToPort": rule.get("ToPort"),
                                               "IpRanges": [{"CidrIp": ip.get("CidrIp")} for ip in rule.get("IpRanges", [])],
                                               "Ipv6Ranges": [{"CidrIpv6": ip.get("CidrIpv6")} for ip in rule.get("Ipv6Ranges", [])]}
                                              for rule in item.get("IpPermissions", [])] if "IpPermissions" in item else None,
                                  "vpc": item.get("VpcId"),
                                  "tags": self.tags(item.get("Tags", []))})
                    elif kind == "ec2.volume":
                        self.add(kind, item["VolumeId"], item["VolumeId"], region,
                                 {"encrypted": item.get("Encrypted"), "size_gib": item.get("Size"),
                                  "tags": self.tags(item.get("Tags", []))})
                    else:
                        for instance in item.get("Instances", []):
                            self.add(kind, instance["InstanceId"], instance["InstanceId"], region,
                                     {"http_tokens": instance.get("MetadataOptions", {}).get("HttpTokens"),
                                      "public_ip": instance.get("PublicIpAddress"),
                                      "state": instance.get("State", {}).get("Name"),
                                      "security_groups": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
                                      "vpc": instance.get("VpcId"), "subnet": instance.get("SubnetId"),
                                      "instance_type": instance.get("InstanceType"),
                                      "tags": self.tags(instance.get("Tags", []))})

    def s3(self, region):
        with self.section("s3", "global"):
            flags = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            account = self.optional("s3control", region, "get_public_access_block", "PublicAccessBlockConfiguration",
                                    absent={}, absent_codes=("NoSuchPublicAccessBlockConfiguration",), AccountId=self.account)
            for bucket in self.pages("s3", region, "list_buckets", "Buckets"):
                name = bucket["Name"]
                prior_coverage = len(self.snapshot.coverage)
                location = self.optional("s3", region, "get_bucket_location", "LocationConstraint", Bucket=name,
                                         ExpectedBucketOwner=self.account)
                # A null LocationConstraint means us-east-1; access denial also returns None.
                # Only read buckets in selected regions; unknown location is not silently assumed.
                unknown_location = len(self.snapshot.coverage) != prior_coverage
                if location is None and unknown_location:
                    continue
                location = "eu-west-1" if location == "EU" else location or "us-east-1"
                if location not in self.config["regions"]:
                    continue
                block = self.optional("s3", location, "get_public_access_block", "PublicAccessBlockConfiguration",
                                      absent={}, absent_codes=("NoSuchPublicAccessBlockConfiguration",), Bucket=name,
                                      ExpectedBucketOwner=self.account)
                effective = None if block is None or account is None else {
                    flag: bool(block.get(flag) or account.get(flag)) for flag in flags}
                policy = self.optional("s3", location, "get_bucket_policy_status", "PolicyStatus", absent={"IsPublic": False},
                                       absent_codes=("NoSuchBucketPolicy",), Bucket=name, ExpectedBucketOwner=self.account)
                public = None if policy is None else bool(policy.get("IsPublic"))
                if effective and effective.get("RestrictPublicBuckets"):
                    public = False
                versioning = self.optional("s3", location, "get_bucket_versioning", "Status", absent="Disabled",
                                           Bucket=name, ExpectedBucketOwner=self.account)
                self.add("s3.bucket", f"arn:aws:s3:::{name}", name, location,
                         {"block_public_access": effective, "policy_public": public, "versioning": versioning,
                          "tags": {}})

    def rds(self, region):
        with self.section("rds", region):
            for item in self.pages("rds", region, "describe_db_instances", "DBInstances"):
                self.add("rds.instance", item["DBInstanceArn"], item["DBInstanceIdentifier"], region,
                         {"public": item.get("PubliclyAccessible"), "encrypted": item.get("StorageEncrypted"),
                          "backup_days": item.get("BackupRetentionPeriod"),
                          "deletion_protection": item.get("DeletionProtection"),
                          "security_groups": [g["VpcSecurityGroupId"] for g in item.get("VpcSecurityGroups", [])],
                          "engine": item.get("Engine"), "tags": self.tags(item.get("TagList", []))})

    def iam(self, region):
        with self.section("iam", "global"):
            summary = self.call("iam", region, "get_account_summary")["SummaryMap"]
            self.add("iam.account", f"arn:aws:iam::{self.account}:root", "AWS account identity", "global",
                     {"root_mfa": bool(summary["AccountMFAEnabled"]) if "AccountMFAEnabled" in summary else None,
                      "users": summary.get("Users"), "roles": summary.get("Roles"), "tags": {}})

    def cloudtrail(self, region):
        with self.section("cloudtrail", "global"):
            trails = self.call("cloudtrail", region, "describe_trails", includeShadowTrails=True)["trailList"]
            active, unknown = False, False
            for trail in trails:
                if not trail.get("IsMultiRegionTrail"):
                    continue
                home = trail.get("HomeRegion", region)
                with self.section("cloudtrail", home, "get_trail_status"):
                    status = self.call("cloudtrail", home, "get_trail_status", Name=trail["TrailARN"])
                    active |= bool(status.get("IsLogging"))
                    unknown |= "IsLogging" not in status
                if self.snapshot.coverage[-1]["status"] != "complete":
                    unknown = True
            self.add("cloudtrail.account", f"aws:{self.account}:cloudtrail", "Management trail coverage", "global",
                     {"logging_multiregion": True if active else None if unknown else False,
                      "trail_count": len(trails), "tags": {}})

    def eks(self, region):
        with self.section("eks", region):
            for name in self.pages("eks", region, "list_clusters", "clusters"):
                with self.section("eks", region, "describe_cluster"):
                    cluster = self.call("eks", region, "describe_cluster", name=name)["cluster"]
                    vpc = cluster.get("resourcesVpcConfig", {})
                    enabled = [entry for entry in cluster.get("logging", {}).get("clusterLogging", []) if entry.get("enabled")]
                    self.add("eks.cluster", cluster["arn"], name, region,
                             {"public_unrestricted": None if "endpointPublicAccess" not in vpc or (
                                 vpc["endpointPublicAccess"] and "publicAccessCidrs" not in vpc) else bool(vpc.get("endpointPublicAccess") and any(
                                 cidr in ("0.0.0.0/0", "::/0") for cidr in vpc.get("publicAccessCidrs", []))),
                              "audit_logging": any("audit" in entry.get("types", []) for entry in enabled) if "logging" in cluster else None,
                              "tags": {k: v[:256] for k, v in cluster.get("tags", {}).items()
                                       if k.lower() in ("environment", "env", "repository", "source-repo", "team")}})

    def collect(self):
        try:
            for service in self.config["services"]:
                for region in self.config["regions"]:
                    getattr(self, service)(region)
                    if service in ("s3", "iam", "cloudtrail"):
                        break
        except CollectionLimit as exc:
            self.snapshot.coverage.append({"service": "scan", "region": "all", "status": "limited", "error": str(exc)})
        # Record skipped scopes when an early resource or API cap stopped collection.
        for service in self.config["services"]:
            for region in (["global"] if service in ("s3", "iam", "cloudtrail") else self.config["regions"]):
                if not any(c["service"] == service and c["region"] == region for c in self.snapshot.coverage):
                    self.snapshot.coverage.append({"service": service, "region": region, "status": "not_collected"})
        return self.snapshot


def demo_snapshot():
    """Entirely synthetic configuration; never reads the operator's AWS environment."""
    return Snapshot(resources=[
        {"kind": "ec2.security_group", "uid": "sg-demo-web", "name": "production-web", "region": "us-east-1",
         "data": {"ingress": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "tags": {"environment": "production"}}},
        {"kind": "ec2.instance", "uid": "i-demo-web", "name": "customer-api", "region": "us-east-1",
         "data": {"http_tokens": "optional", "public_ip": "203.0.113.10", "security_groups": ["sg-demo-web"],
                  "state": "running", "tags": {"environment": "production", "repository": "example/customer-api"}}},
        {"kind": "rds.instance", "uid": "demo:db:orders", "name": "orders", "region": "us-east-1",
         "data": {"public": False, "encrypted": True, "backup_days": 0, "deletion_protection": False,
                  "security_groups": ["sg-demo-db"], "tags": {"environment": "production"}}},
        {"kind": "s3.bucket", "uid": "arn:aws:s3:::example-demo-reports", "name": "example-demo-reports",
         "region": "us-east-1", "data": {"block_public_access": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False}, "policy_public": True,
            "versioning": "Disabled", "tags": {}}},
        {"kind": "ec2.volume", "uid": "vol-demo-app", "name": "app-storage", "region": "us-east-1",
         "data": {"encrypted": True, "size_gib": 24, "tags": {}}},
    ], coverage=[{"service": "demo", "region": "us-east-1", "status": "complete", "synthetic": True}])
