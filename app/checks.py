"""Small, reviewable configuration rules. None of these modifies cloud resources."""
from dataclasses import dataclass
from ipaddress import ip_network

AWS = "https://docs.aws.amazon.com/securityhub/latest/userguide/"


@dataclass(frozen=True)
class Check:
    id: str
    kind: str
    title: str
    severity: str
    field: str
    predicate: object
    remediation: str
    reference: str


CHECKS = [
    Check("MC-S3-001", "s3.bucket", "S3 public-access safeguards are incomplete", "medium", "block_public_access",
          lambda d: all(d.values()) and len(d) == 4,
          "Enable all four Block Public Access flags at the bucket or account level after reviewing access needs.",
          AWS + "s3-controls.html#s3-8"),
    Check("MC-S3-002", "s3.bucket", "S3 policy is classified public without effective bucket restriction", "high",
          "policy_public", lambda d: not d,
          "Review the bucket policy and enable effective RestrictPublicBuckets protection.", AWS + "s3-controls.html"),
    Check("MC-S3-003", "s3.bucket", "S3 versioning is disabled", "low", "versioning", lambda d: d == "Enabled",
          "Enable bucket versioning and review lifecycle retention costs.", AWS + "s3-controls.html#s3-14"),
    Check("MC-EC2-001", "ec2.security_group", "Security group permits unrestricted SSH ingress", "high", "ingress",
          lambda d: not public_ingress(d, 22),
          "Restrict SSH to trusted networks or use Session Manager; evaluate routes and network ACLs separately.",
          AWS + "ec2-controls.html#ec2-13"),
    Check("MC-EC2-002", "ec2.security_group", "Security group permits unrestricted RDP ingress", "high", "ingress",
          lambda d: not public_ingress(d, 3389),
          "Restrict RDP to trusted networks and evaluate routes, network ACLs and public addressing.",
          AWS + "ec2-controls.html#ec2-14"),
    Check("MC-EC2-003", "ec2.instance", "EC2 does not require IMDSv2", "medium", "http_tokens",
          lambda d: d == "required", "Require IMDSv2 after validating workload compatibility.",
          AWS + "ec2-controls.html#ec2-8"),
    Check("MC-EBS-001", "ec2.volume", "EBS volume is unencrypted", "medium", "encrypted", bool,
          "Migrate to an encrypted volume through a reviewed change; this tool never snapshots volumes.",
          AWS + "ec2-controls.html#ec2-3"),
    Check("MC-RDS-001", "rds.instance", "RDS is configured as publicly accessible", "high", "public", lambda d: not d,
          "Disable public accessibility and verify private application connectivity and security groups.",
          AWS + "rds-controls.html#rds-2"),
    Check("MC-RDS-002", "rds.instance", "RDS storage is unencrypted", "medium", "encrypted", bool,
          "Plan a reviewed migration to encrypted storage; MayoCSPM does not copy databases.",
          AWS + "rds-controls.html#rds-3"),
    Check("MC-RDS-003", "rds.instance", "RDS automated backup retention is disabled", "medium", "backup_days",
          lambda d: d > 0, "Choose an automated backup retention period appropriate to the recovery objective.",
          AWS + "rds-controls.html#rds-11"),
    Check("MC-RDS-004", "rds.instance", "RDS deletion protection is disabled", "low", "deletion_protection", bool,
          "Enable deletion protection for persistent databases.", AWS + "rds-controls.html#rds-8"),
    Check("MC-IAM-001", "iam.account", "Root account MFA is not enabled", "high", "root_mfa", bool,
          "Enable MFA on the AWS root identity and follow AWS root-account security guidance.",
          AWS + "iam-controls.html#iam-9"),
    Check("MC-CT-001", "cloudtrail.account", "No logging multi-region CloudTrail was observed", "high", "logging_multiregion",
          bool, "Enable a logging multi-region management-event trail; review organization trails and event selectors.",
          AWS + "cloudtrail-controls.html#cloudtrail-1"),
    Check("MC-EKS-001", "eks.cluster", "EKS API public endpoint allows unrestricted CIDRs", "high", "public_unrestricted",
          lambda d: not d, "Restrict the public endpoint CIDRs or use a private endpoint after validating access.",
          AWS + "eks-controls.html#eks-1"),
    Check("MC-EKS-002", "eks.cluster", "EKS audit control-plane logging is disabled", "medium", "audit_logging", bool,
          "Enable audit control-plane logging and configure log retention.", AWS + "eks-controls.html#eks-8"),
]


def public_ingress(rules, port):
    for rule in rules:
        protocol = str(rule.get("IpProtocol", ""))
        if protocol not in ("-1", "tcp", "6"):
            continue
        if protocol != "-1":
            low, high = rule.get("FromPort"), rule.get("ToPort")
            if low is None or high is None or not low <= port <= high:
                continue
        cidrs = [x.get("CidrIp") for x in rule.get("IpRanges", [])]
        cidrs += [x.get("CidrIpv6") for x in rule.get("Ipv6Ranges", [])]
        for cidr in cidrs:
            if cidr and ip_network(cidr, strict=False).prefixlen == 0:
                return True
    return False


def risk(severity, data):
    base = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}.get(severity, 45)
    reasons = [f"{severity} base: {base}"]
    tags = {str(k).lower(): str(v).lower() for k, v in data.get("tags", {}).items()}
    if tags.get("environment", tags.get("env")) in ("prod", "production"):
        base += 10
        reasons.append("production tag: +10")
    if data.get("public_ip") or data.get("public") or data.get("public_unrestricted") or data.get("policy_public"):
        base += 10
        reasons.append("public configuration observed: +10 (reachability not verified)")
    return min(base, 100), reasons


def evaluate(resource):
    results = []
    for check in CHECKS:
        if check.kind != resource["kind"]:
            continue
        data = resource["data"]
        value = data.get(check.field)
        status = "unknown" if value is None else ("pass" if check.predicate(value) else "fail")
        score, reasons = risk(check.severity, data)
        results.append({"check_id": check.id, "status": status, "title": check.title, "severity": check.severity,
                        "score": score, "reasons": reasons, "evidence": {check.field: value},
                        "remediation": check.remediation, "reference": check.reference})
    return results
