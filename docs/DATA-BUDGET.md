# Collection and storage contract

MayoCSPM collects configuration metadata through an explicit list of AWS read APIs.
It does **not** snapshot disks or workloads, copy ECR images, pull image layers,
read S3 objects, retrieve secret values, read database contents, run repository
code, or automatically remediate cloud resources. Even EBS collection is only
volume identifiers, size, encryption state, attached instance IDs and selected tags.

## Enforced limits

| Boundary | Default / hard limit |
| --- | --- |
| Selected commercial AWS regions | 1 / 4 |
| Resources in one scan | 1,000 / 5,000 |
| Logical collector API calls | 300 / 1,000 |
| SDK HTTP attempts per call | At most 2, including initial attempt |
| AWS pagination | 100 items per page, API budget enforced before each next page |
| Normalized resource metadata | 8 MiB per scan |
| Collection wall deadline | 600 seconds, checked between calls |
| SDK timeouts | 3-second connect / 12-second read |
| Workspace connections / instance workspaces | 10 / 100 |
| Workspace members / active API keys | 100 / 100 |
| Workspace findings | 50,000; oversized writes roll back |
| Scheduled collection interval | 1–168 hours, 0 pauses |
| Manual scan or report import | At most one per connection per 5 minutes |
| Graph snapshot | First 1,000 resources, 2,000 findings, 10,000 relationships; explicit warnings |
| Graph metadata | 4 MiB conservative JSON admission; field limit 65,536 SQL characters |
| Graph API / context | 768 KiB / 384 KiB diagram payload; context 150 nodes / 300 edges |
| Candidate paths | 4 hops, 20 paths, 10,000 search operations |
| MQL query | 8,192 characters, 512 tokens, 3 joined patterns, 4 hops |
| MQL evaluation | 25,000 operations, cooperative 2 seconds, 5,000 intermediate matches / 2 MiB projection accounting |
| MQL response | 200 rows / 512 KiB, matched graph 100 nodes / 200 edges / 384 KiB |
| Graph/query concurrency | 2 active reads per API process; excess work receives 503 |
| Shared saved queries | 50 per workspace; query text up to 8,192 characters |
| Diagram UI | Up to 100 matching nodes / 200 connections, visibly disclosed |
| Resource / finding query page | 100 default / 200 hard cap |
| HTTP request / SARIF | 2 MiB request, 1,000 SARIF results |
| GitHub alert synchronization | 500 results total, 6 pages per alert category |
| Runtime limits | App 384 MiB, worker 512 MiB, PostgreSQL 384 MiB; 0.5 CPU each |
| Logs | Three 10 MiB files per service |

Budgets are conservative logical calls. Pagination counts an end-of-iteration
probe even when it issues no request. SDK retries can double wire attempts;
initial role validation uses three STS AssumeRole calls and one identity call
outside the collector budget. Later scans use one AssumeRole and one identity
call. These limits are not a promise of zero AWS charges: service billing and
network costs depend on the customer's configuration. See
[AWS API documentation](https://docs.aws.amazon.com/) for relevant services.

Single service requests can take longer than their nominal read timeout across
connection setup and SDK retries. The collector checks its deadline before the
next operation; it does not terminate an in-flight SDK call. Container memory
limits provide the final runtime memory boundary. Initial image builds have
their own host-level CPU, RAM, disk and network requirements.

## What is stored

Only the latest collected resource metadata is retained for a connection. A new
partial scan replaces the visible snapshot with its observed subset; earlier
finding evidence remains, with its own last-observed timestamp. Collection scopes
record complete, unknown, limited, or not-collected status. A graph or inventory
query describes that snapshot, not live AWS state; run another scan to update it.

Resource fields are deliberately selected: identifiers, region, resource type,
public configuration flags, encryption/backup settings, security-group CIDRs and
ports, selected ownership/context tags, and limited account counts. S3 bucket
tags are not collected in this preview. Tag allowlists reduce collection but do
not make inventory non-sensitive; names, paths and tag values can reveal internal
architecture. Protect the database and exports as security-sensitive data.

Findings preserve first/last observation, a stable identity, check evidence,
severity, explainable score and remediation guidance. Resolved findings expire
after 90 days. Open and accepted findings are retained until a passing check,
even if the resource disappears. This avoids clearing risk when permissions are
lost, but open-finding growth can reach the 50,000 finding budget. No automatic
archival or deletion of open findings is implemented; export and review a new
retention policy before reaching that cap.

Audit history expires after 30 days and is capped at 10,000 rows per workspace.
Up to 50 older terminal jobs plus the current snapshot's job are retained per
connection. Retention runs after successful/partial worker scans; the report
import path also applies retention. A dormant instance does not purge on a timer.
Accounts, memberships and revoked credentials are currently retained; do not
interpret these count bounds as a complete data-deletion or privacy contract.

Raw GitHub API responses and raw SARIF are not saved. SARIF messages, snippets,
absolute paths and matched secret text are discarded. Findings retain scanner
rule IDs and relative paths/line numbers. Repository source is not cloned.

## Disk is a separate budget

Compose CPU and memory limits do **not** cap database files, WAL, Docker image
layers or backups. The metadata byte limit bounds one scan; finding history and
indexes add storage overhead. PostgreSQL `max_wal_size` is a checkpoint target,
not an absolute filesystem quota. Use a dedicated filesystem/dataset with a
quota, choose backup retention, and monitor free space. Start with 10 GiB free
for the stack, measure real growth, and alert well before exhaustion. Do not
mount an existing project's database into this stack.

Automatic disk-space admission control and tenant storage-byte quotas remain
planned work; current safeguards are cardinality, report-size, runtime, and
per-scan metadata bounds. A failed database write rolls back and fails the job.

[MQL limits and unknown-value semantics](QUERY-LANGUAGE.md) apply to search and
counts. PostgreSQL graph statements have a two-second timeout; SQLite uses a
progress deadline. Traversal deadlines are cooperative, not HTTP wall-time guarantees.
Byte limits can further reduce graph/results. Skipped metadata remains unknown,
partial counts are lower bounds, and truncation never establishes absence of risk.
