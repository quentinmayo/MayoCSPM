"""Optional GitHub alerts and bounded SARIF ingestion, without cloning or executing code."""
import hashlib
import json
from urllib.parse import urlparse

import httpx

from app.collectors import Snapshot
from app.security import github_repo


def repository_resource(repo):
    github_repo(repo)
    return {"uid": f"https://github.com/{repo}", "name": repo, "kind": "github.repository", "region": "global",
            "data": {"tags": {}, "repository": repo}}


def observation(uid, check_id, title, severity, evidence, reference="https://docs.github.com/en/code-security"):
    severity = severity if severity in ("critical", "high", "medium", "low", "info") else "medium"
    # Store locations and rule identifiers. Never retain snippets, matched secrets or report messages.
    return {"resource_uid": uid, "check_id": check_id[:120], "title": title[:300], "severity": severity,
            "score": {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}[severity],
            "reasons": ["scanner severity; reachability not assessed"], "evidence": evidence,
            "remediation": "Review the originating scanner rule and remediate the affected source or dependency.",
            "reference": reference, "status": "fail"}


def collect_github(repo, token, max_alerts=500):
    resource = repository_resource(repo)
    result = Snapshot(resources=[resource])
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "Authorization": "Bearer " + token}
    with httpx.Client(base_url="https://api.github.com", headers=headers, timeout=15, follow_redirects=False,
                      trust_env=False) as client:
        for category in ("code-scanning", "dependabot"):
            entry = {"service": "github", "region": "global", "scope": category, "status": "complete"}
            result.coverage.append(entry)
            for page in range(1, 7):
                result.api_calls += 1
                with client.stream("GET", f"/repos/{repo}/{category}/alerts", params={"state": "open", "per_page": 100,
                                                                                   "page": page}) as response:
                    if response.status_code != 200:
                        entry.update(status="unknown", error=f"HTTP{response.status_code}")
                        break
                    chunks, length = [], 0
                    for chunk in response.iter_bytes(chunk_size=65536):
                        length += len(chunk)
                        if length > 2 * 1024 * 1024:
                            entry.update(status="limited", error="response_size_limit")
                            break
                        chunks.append(chunk)
                if entry["status"] != "complete":
                    break
                try:
                    alerts = json.loads(b"".join(chunks))
                    if not isinstance(alerts, list):
                        raise ValueError
                except ValueError:
                    entry.update(status="unknown", error="invalid_response")
                    break
                for alert in alerts:
                    if len(result.observations) >= max_alerts:
                        entry.update(status="limited", error="alert_limit")
                        break
                    rule = alert.get("rule", {})
                    advisory = alert.get("security_advisory", {})
                    severity = rule.get("security_severity_level") or advisory.get("severity", "medium")
                    rule_id = rule.get("id") or advisory.get("ghsa_id", "dependency")
                    evidence = {"category": category, "rule": str(rule_id)[:120], "alert_number": alert["number"]}
                    location = alert.get("most_recent_instance", {}).get("location", {})
                    if location:
                        evidence.update(path=str(location.get("path", ""))[:512], line=location.get("start_line"))
                    result.observations.append(observation(resource["uid"], f"GH-{category}-{alert['number']}",
                                                          f"{category}: {rule_id}", severity, evidence))
                if entry["status"] != "complete" or len(alerts) < 100:
                    break
            else:
                entry.update(status="limited", error="page_limit")
    return result


def parse_sarif(repo, document):
    resource = repository_resource(repo)
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("A SARIF 2.1.0 document with runs is required")
    result = Snapshot(resources=[resource], coverage=[{"service": "sarif", "region": "global",
                                                     "status": "complete", "scope": "uploaded_report"}])
    count = 0
    for run in document["runs"]:
        tool = str(run.get("tool", {}).get("driver", {}).get("name", "scanner"))[:80]
        for item in run.get("results", []):
            count += 1
            if count > 1000:
                raise ValueError("SARIF import is limited to 1000 results")
            rule = str(item.get("ruleId", "unknown"))[:120]
            locations = item.get("locations", [])
            location = locations[0].get("physicalLocation", {}) if locations else {}
            path = str(location.get("artifactLocation", {}).get("uri", ""))[:512]
            if urlparse(path).scheme or path.startswith("/") or ".." in path.split("/"):
                path = "[non-relative location omitted]"
            line = location.get("region", {}).get("startLine")
            if not isinstance(line, int) or line < 1:
                line = None
            unique = hashlib.sha256(f"{tool}|{rule}|{path}|{line}".encode()).hexdigest()[:32]
            level = item.get("level", "warning")
            severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")
            result.observations.append(observation(resource["uid"], f"SARIF-{unique}", f"{tool}: {rule}", severity,
                                                   {"tool": tool, "rule": rule, "path": path, "line": line}))
    return result
