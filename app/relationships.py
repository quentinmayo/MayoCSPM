"""Bounded, workspace-local evidence graph. No live provider calls or credentials."""

import hashlib
import json
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from ipaddress import ip_network
from threading import BoundedSemaphore
from time import monotonic

from sqlalchemy import Text, cast, func, select

from app.db import Connection, Finding, Job, Resource
from app.service import current_resources, effective_status

RESOURCE_LIMIT = 1000
FINDING_LIMIT = 2000
EDGE_LIMIT = 10000
METADATA_LIMIT = 4 * 1024 * 1024
FIELD_LIMIT = 65536
MODEL = "Configuration relationships; candidate exposure is not proof of a reachable attack path."
NETWORK_LIMIT = "Routes, NACLs, listeners and end-to-end reachability are unverified."
RELATIONS = {
    "PUBLIC_CONFIGURATION": "public configuration",
    "SECURITY_GROUP_ATTACHED": "security group attached",
    "USES_VOLUME": "volume attached to workload",
    "ALLOWS_GROUP": "ingress references security group",
    "LOGS_TO": "configured CloudTrail log destination",
    "DEPLOYS_TO": "explicit repository tag",
    "HAS_FINDING": "recorded finding",
    "CONTAINS": "source contains resource",
    "REPORTED": "source reported finding",
}
READ_SLOTS = BoundedSemaphore(2)


class GraphBusy(Exception):
    pass


@contextmanager
def graph_read(db):
    """No waiting queue: cap graph memory/CPU concurrency per API process."""
    if not READ_SLOTS.acquire(blocking=False):
        raise GraphBusy
    driver = None
    try:
        if db.bind.dialect.name == "postgresql":
            db.execute(select(func.set_config("statement_timeout", "2000", True)))
        elif db.bind.dialect.name == "sqlite":
            driver = db.connection().connection.driver_connection
            deadline = monotonic() + 2
            driver.set_progress_handler(lambda: int(monotonic() > deadline), 10000)
        yield
    finally:
        if driver is not None:
            driver.set_progress_handler(None, 0)
        READ_SLOTS.release()


def stamp(value):
    return value.isoformat() + "Z" if value else None


@dataclass
class Snapshot:
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    warnings: set = field(default_factory=set)
    coverage: list = field(default_factory=list)
    metadata_used: int = 0
    _edge_ids: set = field(default_factory=set)

    def edge(self, source, target, kind, confidence="observed", evidence=None, limitations=""):
        if source not in self.nodes or target not in self.nodes:
            return
        identity = hashlib.sha256(f"{source}|{kind}|{target}".encode()).hexdigest()[:24]
        if identity in self._edge_ids:
            return
        if len(self.edges) >= EDGE_LIMIT:
            self.warnings.add("relationship_limit")
            return
        self._edge_ids.add(identity)
        self.edges.append(
            {
                "id": identity,
                "source": source,
                "target": target,
                "type": kind,
                "relation": RELATIONS[kind],
                "confidence": confidence,
                "evidence": evidence or {},
                "limitations": limitations,
            }
        )

    def summary(self, node_id):
        node = self.nodes[node_id]
        return {k: v for k, v in node.items() if k not in ("data", "evidence", "remediation", "reasons")}

    def metadata(self):
        return {
            "warnings": sorted(self.warnings),
            "truncated": bool(self.warnings),
            "coverage": self.coverage,
            "model": MODEL,
            "limits": {
                "resources": RESOURCE_LIMIT,
                "findings": FINDING_LIMIT,
                "relationships": EDGE_LIMIT,
                "metadata_mib": 4,
            },
        }


def public_rules(data):
    """Retain a small explanation for any world CIDR, not only SSH/RDP."""
    rules = data.get("ingress")
    if not isinstance(rules, list):
        return None
    result = []
    try:
        for rule in rules:
            for entry in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", []):
                cidr = entry.get("CidrIp", entry.get("CidrIpv6"))
                if cidr and ip_network(cidr, strict=False).prefixlen == 0:
                    result.append(
                        {
                            "cidr": cidr,
                            "protocol": rule.get("IpProtocol"),
                            "from_port": rule.get("FromPort"),
                            "to_port": rule.get("ToPort"),
                        }
                    )
                    if len(result) == 20:
                        return result
    except (ValueError, TypeError, AttributeError):
        return None
    return result


def exposure(node):
    data, kind = node.get("data"), node["kind"]
    if not isinstance(data, dict):
        return "unknown", {}, "Resource metadata was unavailable or exceeded the query budget."
    if kind == "ec2.security_group":
        rules = public_rules(data)
        return (
            "unknown" if rules is None else "potential" if rules else "not_observed",
            {"public_ingress": rules},
            NETWORK_LIMIT,
        )
    if kind == "s3.bucket":
        block = data.get("block_public_access")
        public = data.get("policy_public")
        restricted = block.get("RestrictPublicBuckets") if isinstance(block, dict) else None
        state = "unknown" if public is None else "potential" if public and restricted is not True else "not_observed"
        return (
            state,
            {"policy_public": public, "block_public_access": block},
            (
                "Policy classification and effective account/bucket safeguards only. Object ACLs, access points, "
                "organization-policy collection and anonymous object access are not independently verified."
            ),
        )
    key = {"ec2.instance": "public_ip", "rds.instance": "public", "eks.cluster": "public_unrestricted"}.get(kind)
    if key:
        value = data.get(key)
        # EC2 absence of a public address is an observed configuration, not proof of privacy.
        state = "potential" if value else "not_observed" if key in data else "unknown"
        if value is None and key != "public_ip":
            state = "unknown"
        return state, {key: value}, NETWORK_LIMIT
    return "not_observed", {}, "This resource type has no public-exposure rule in this preview."


def _metadata(db, model, ids, fields, snapshot, workspace_id):
    """Size admission precedes JSON loading; oversize fields remain unknown."""
    selected = []
    for object_id, sizes in ids:
        # SQL character lengths are conservatively charged at four UTF-8 bytes.
        charge = sum((size or 0) * 4 for size in sizes)
        if any((size or 0) > FIELD_LIMIT for size in sizes) or snapshot.metadata_used + charge > METADATA_LIMIT:
            snapshot.warnings.add("metadata_limit")
            continue
        snapshot.metadata_used += charge
        selected.append(object_id)
    if not selected:
        return {}
    # IDs came from the workspace-scoped first query, not from caller input.
    return {
        row[0]: dict(zip(fields, row[1:], strict=True))
        for row in db.execute(
            select(model.id, *(getattr(model, name) for name in fields)).where(
                model.workspace_id == workspace_id, model.id.in_(selected)
            )
        )
    }


def load_snapshot(db, workspace_id):
    snapshot = Snapshot()
    snapshot.nodes["internet"] = {
        "id": "internet",
        "entity": "Internet",
        "name": "Internet",
        "label": "Internet",
        "kind": "context",
        "exposure": "context",
    }
    connections = list(
        db.execute(
            select(Connection.id, Connection.name, Connection.kind, Connection.validated, Connection.latest_job_id)
            .where(Connection.workspace_id == workspace_id)
            .order_by(Connection.id)
            .limit(11)
        )
    )
    if len(connections) > 10:
        snapshot.warnings.add("connection_limit")
    connections = connections[:10]
    connection_ids = [c.id for c in connections]
    for c in connections:
        snapshot.nodes[f"connection:{c.id}"] = {
            "id": f"connection:{c.id}",
            "entity": "Connection",
            "connection_id": c.id,
            "name": c.name,
            "label": c.name,
            "kind": c.kind,
            "validated": c.validated,
        }
    if not connection_ids:
        return snapshot
    rows = list(
        db.execute(
            current_resources(db, workspace_id)
            .with_only_columns(
                Resource.id,
                Resource.connection_id,
                Resource.uid,
                Resource.kind,
                Resource.name,
                Resource.region,
                Resource.seen,
                func.length(cast(Resource.data, Text)).label("size"),
            )
            .where(Resource.connection_id.in_(connection_ids))
            .order_by(Resource.id)
            .limit(RESOURCE_LIMIT + 1)
        )
    )
    if len(rows) > RESOURCE_LIMIT:
        snapshot.warnings.add("resource_limit")
    rows = rows[:RESOURCE_LIMIT]
    data = _metadata(db, Resource, [(r.id, [r.size]) for r in rows], ["data"], snapshot, workspace_id)
    resource_ids = {}
    for r in rows:
        node_id = f"{r.connection_id}:{r.uid}"
        resource_ids[(r.connection_id, r.uid)] = node_id
        node = {
            "id": node_id,
            "entity": "Resource",
            "resource_id": r.id,
            "connection_id": r.connection_id,
            "uid": r.uid,
            "name": r.name,
            "label": r.name,
            "kind": r.kind,
            "region": r.region,
            "seen": stamp(r.seen),
            "data": data.get(r.id, {}).get("data"),
            "finding_count": 0,
        }
        node["exposure"], node["exposure_evidence"], node["limitations"] = exposure(node)
        snapshot.nodes[node_id] = node
        snapshot.edge(f"connection:{r.connection_id}", node_id, "CONTAINS")
        if node["exposure"] == "potential":
            snapshot.edge(
                "internet", node_id, "PUBLIC_CONFIGURATION", "candidate", node["exposure_evidence"], node["limitations"]
            )
    resources = [n for n in snapshot.nodes.values() if n["entity"] == "Resource"]
    groups = {
        (n["connection_id"], n["region"], n["uid"].split("/")[-1]): n["id"]
        for n in resources
        if n["kind"] == "ec2.security_group"
    }
    instances = {
        (n["connection_id"], n["region"], n["uid"].split("/")[-1]): n["id"]
        for n in resources
        if n["kind"] == "ec2.instance"
    }
    buckets = {(n["connection_id"], n["name"]): n["id"] for n in resources if n["kind"] == "s3.bucket"}
    repositories = defaultdict(list)
    for n in resources:
        if n["kind"] == "github.repository":
            repositories[n["uid"].lower()].append(n["id"])
    for n in resources:
        d = n["data"] if isinstance(n["data"], dict) else {}
        for group_id in items(d.get("security_groups")):
            if not isinstance(group_id, str):
                continue
            source = groups.get((n["connection_id"], n["region"], group_id))
            if source:
                snapshot.edge(
                    source,
                    n["id"],
                    "SECURITY_GROUP_ATTACHED",
                    evidence={"group_id": group_id},
                    limitations=NETWORK_LIMIT,
                )
        if n["kind"] == "ec2.security_group":
            for rule in items(d.get("ingress")):
                if not isinstance(rule, dict):
                    continue
                for pair in items(rule.get("UserIdGroupPairs")):
                    if not isinstance(pair, dict) or not isinstance(pair.get("GroupId"), str):
                        continue
                    source = groups.get((n["connection_id"], n["region"], pair.get("GroupId")))
                    if source and pair.get("UserId"):
                        parts = snapshot.nodes[source]["uid"].split(":")
                        if len(parts) < 6 or parts[4] != pair["UserId"]:
                            # Cross-account references need explicit source identity;
                            # a matching short group ID alone is not evidence.
                            continue
                    if source:
                        snapshot.edge(
                            source,
                            n["id"],
                            "ALLOWS_GROUP",
                            evidence={"group_id": pair.get("GroupId"), "account_id": pair.get("UserId")},
                            limitations="Security-group reference only; not transitive access or verified routing.",
                        )
        if n["kind"] == "ec2.volume":
            for instance_id in items(d.get("attached_instances")):
                if not isinstance(instance_id, str):
                    continue
                source = instances.get((n["connection_id"], n["region"], instance_id))
                if source:
                    snapshot.edge(
                        source,
                        n["id"],
                        "USES_VOLUME",
                        evidence={"instance_id": instance_id},
                        limitations="Observed attachment; does not prove data access or compromise.",
                    )
        if n["kind"] == "cloudtrail.account":
            for bucket_name in items(d.get("storage_buckets")):
                if not isinstance(bucket_name, str):
                    continue
                target = buckets.get((n["connection_id"], bucket_name))
                if target:
                    snapshot.edge(
                        n["id"],
                        target,
                        "LOGS_TO",
                        evidence={"bucket_name": bucket_name},
                        limitations="Configured destination only; log delivery and bucket permissions are unverified.",
                    )
        tags = d.get("tags") if isinstance(d.get("tags"), dict) else {}
        repo = tags.get("repository", tags.get("source-repo", ""))
        if not isinstance(repo, str):
            continue
        repo = repo.removeprefix("https://github.com/").removesuffix(".git").rstrip("/").lower()
        for source in repositories.get("https://github.com/" + repo, []):
            snapshot.edge(
                source,
                n["id"],
                "DEPLOYS_TO",
                "declared",
                {"repository_tag": repo},
                "Operator-declared repository association; deployment provenance is unverified.",
            )
    rows = list(
        db.execute(
            select(
                Finding.id,
                Finding.connection_id,
                Finding.resource_uid,
                Finding.title,
                Finding.severity,
                Finding.score,
                Finding.status,
                Finding.accepted_until,
                Finding.last_seen,
                Finding.check_id,
                func.substr(Finding.remediation, 1, 4000).label("remediation"),
                func.length(cast(Finding.evidence, Text)).label("size"),
            )
            .join(Connection, Connection.id == Finding.connection_id)
            .where(
                Finding.workspace_id == workspace_id,
                Connection.workspace_id == workspace_id,
                Finding.connection_id.in_(connection_ids),
            )
            .order_by(Finding.score.desc(), Finding.id)
            .limit(FINDING_LIMIT + 1)
        )
    )
    if len(rows) > FINDING_LIMIT:
        snapshot.warnings.add("finding_limit")
    rows = rows[:FINDING_LIMIT]
    evidence = _metadata(db, Finding, [(r.id, [r.size]) for r in rows], ["evidence"], snapshot, workspace_id)
    for r in rows:
        resource = resource_ids.get((r.connection_id, r.resource_uid))
        node = {
            "id": f"finding:{r.id}",
            "entity": "Finding",
            "finding_id": r.id,
            "connection_id": r.connection_id,
            "resource_uid": r.resource_uid,
            "name": r.title,
            "label": r.title,
            "severity": r.severity,
            "score": r.score,
            "status": effective_status(r),
            "last_seen": stamp(r.last_seen),
            "check_id": r.check_id,
            "resource_current": True if resource else None if "resource_limit" in snapshot.warnings else False,
            "remediation": r.remediation,
            "evidence": evidence.get(r.id, {}).get("evidence"),
        }
        snapshot.nodes[node["id"]] = node
        snapshot.edge(f"connection:{r.connection_id}", node["id"], "REPORTED")
        if resource:
            snapshot.edge(
                resource,
                node["id"],
                "HAS_FINDING",
                evidence={"last_seen": stamp(r.last_seen)},
                limitations="Finding evidence has its own observation time; inspect status and scan coverage.",
            )
            if node["status"] == "open":
                snapshot.nodes[resource]["finding_count"] += 1
    latest_ids = [c.latest_job_id for c in connections if c.latest_job_id]
    for job in db.scalars(select(Job).where(Job.workspace_id == workspace_id, Job.id.in_(latest_ids))):
        gaps = [c for c in job.coverage if c.get("status") != "complete"]
        if gaps or job.status != "completed":
            snapshot.warnings.add("collection_gaps")
        snapshot.coverage.append(
            {
                "connection_id": job.connection_id,
                "job_id": job.id,
                "status": job.status,
                "observed_at": stamp(job.finished),
                "gaps": gaps[:50],
                "gap_count": len(gaps),
            }
        )
    scanned = {c["connection_id"] for c in snapshot.coverage}
    for connection in connections:
        if connection.id not in scanned:
            snapshot.warnings.add("unscanned_connection")
            snapshot.coverage.append(
                {
                    "connection_id": connection.id,
                    "job_id": None,
                    "status": "not_scanned",
                    "observed_at": None,
                    "gaps": [{"status": "unknown", "service": connection.kind}],
                    "gap_count": 1,
                }
            )
    return snapshot


def items(value):
    return value[:256] if isinstance(value, list) else []


def bounded_graph(snapshot, ids, edges, node_limit=1000, edge_limit=2000, byte_limit=768 * 1024):
    nodes, kept, output, size = [], set(), [], 0
    for key in sorted(ids):
        node = snapshot.summary(key)
        charge = len(json.dumps(node, ensure_ascii=True).encode())
        if len(nodes) >= node_limit or size + charge > byte_limit // 2:
            snapshot.warnings.add("result_graph_limit")
            continue
        nodes.append(node)
        kept.add(key)
        size += charge
    for edge in edges:
        if edge["source"] not in kept or edge["target"] not in kept:
            continue
        charge = len(json.dumps(edge, ensure_ascii=True).encode())
        if len(output) >= edge_limit or size + charge > byte_limit:
            snapshot.warnings.add("result_graph_limit")
            continue
        output.append(edge)
        size += charge
    return {"nodes": nodes, "edges": output}


def resource_graph(snapshot):
    ids = {key for key, n in snapshot.nodes.items() if n["entity"] in ("Resource", "Internet")}
    result = bounded_graph(snapshot, ids, snapshot.edges, node_limit=RESOURCE_LIMIT + 1)
    return {**snapshot.metadata(), **result}


def context_graph(snapshot, root, direction="both", depth=2):
    """Evidence neighborhood, excluding source-membership edges from impact context."""
    if root not in snapshot.nodes:
        return None
    adjacency = defaultdict(list)
    for edge in snapshot.edges:
        if edge["type"] in ("CONTAINS", "REPORTED"):
            continue
        if direction in ("out", "both"):
            adjacency[edge["source"]].append((edge["target"], edge))
        if direction in ("in", "both"):
            adjacency[edge["target"]].append((edge["source"], edge))
    ids, edge_ids, frontier = {root}, set(), [root]
    paths = []
    for _ in range(depth):
        next_frontier = []
        for node in frontier:
            for target, edge in adjacency[node]:
                if len(ids) >= 150 or len(edge_ids) >= 300:
                    snapshot.warnings.add("context_limit")
                    continue
                edge_ids.add(edge["id"])
                if target not in ids:
                    ids.add(target)
                    next_frontier.append(target)
        frontier = next_frontier
    # Directional paths from Internet to the selected resource only. Membership,
    # declared code associations and reverse dependencies do not prove exposure.
    forward = defaultdict(list)
    for edge in snapshot.edges:
        if edge["type"] in ("PUBLIC_CONFIGURATION", "SECURITY_GROUP_ATTACHED", "ALLOWS_GROUP", "USES_VOLUME"):
            forward[edge["source"]].append(edge)
    queue = [("internet", [], {"internet"})]
    expansions = 0
    while queue and len(paths) < 20 and expansions < 10000:
        node, path, visited = queue.pop()
        expansions += 1
        if node == root and path:
            paths.append(path)
            continue
        if len(path) == 4:
            continue
        for edge in forward[node]:
            expansions += 1
            if expansions >= 10000:
                snapshot.warnings.add("path_limit")
                break
            if edge["target"] not in visited:
                queue.append((edge["target"], [*path, edge], visited | {edge["target"]}))
                if len(queue) >= 10000:
                    snapshot.warnings.add("path_limit")
                    break
    if queue:
        snapshot.warnings.add("path_limit")
    result = bounded_graph(
        snapshot,
        ids,
        [e for e in snapshot.edges if e["id"] in edge_ids],
        node_limit=150,
        edge_limit=300,
        byte_limit=384 * 1024,
    )
    # Path records refer to IDs only; evidence is on graph edges or the query API.
    path_records = [
        {"nodes": [p[0]["source"], *(e["target"] for e in p)], "edges": [e["id"] for e in p], "length": len(p)}
        for p in paths
    ]
    return {
        **snapshot.metadata(),
        "root": root,
        "direction": direction,
        "depth": depth,
        **result,
        "paths": path_records,
        "interpretation": "Dependency context only. Shared configuration does not prove exploitability or transitive access.",
    }
