# Validation evidence

Checked 2026-10-09. This report separates local/fixture checks from real provider
collection. CheckMayo's earlier results do not validate this new application.

| Check | Evidence |
| --- | --- |
| Automated core suite | 47 passed against actual PostgreSQL 16.13, including concurrent queue admission and GitHub response budgets |
| SQLite development suite | Same suite; PostgreSQL-only concurrency case is skipped |
| Commercial packaging | Landing, console, static assets, protected API, and OpenAPI smoke test passed |
| AWS SDK contract | Stubber tests exercised pagination, scope caps, denied permissions and S3 effective safeguards |
| AWS live metadata | One selected region, six selected services; 16 resources and 51 logical collector calls; eight coverage scopes complete |
| AWS data handling | Real inventory exported to a private mode-600 file outside Git; no identifiers in this report |
| Container deployment | App, worker and PostgreSQL started healthy using Compose |
| Runtime limits | Docker inspection confirmed app 384 MiB, worker 512 MiB, database 384 MiB; 0.5 CPU each; app/worker UID 10001 and read-only root filesystems |
| Browser | Chrome login, all eight app views, inventory filtering and resource inspection passed; nine synthetic screenshots |
| Mobile | 390px viewport; no document overflow or JavaScript errors |
| Dependency advisories | `pip-audit -r requirements.txt` reported no known vulnerabilities at check time |
| Secret handling | Full candidate scan before staging, staged scan before commit, hook enforcement; known private credential comparison before publication |

## Security and correctness coverage

Tests exercise authentication, exact-Origin browser mutations, password/error
redaction, body-size limits, login rate windows, owner protection, viewer/analyst/
admin permissions, workspace collection and child-object isolation, membership
revocation, key hashing/scoping/revocation, temporary risk acceptance expiry,
schedules, encrypted connector tokens, connection caps, invalid role/region input,
SARIF message/snippet removal, relative-path handling, explicit repository links,
IPv4/IPv6 ingress, unknown fields, score explanations, API/resource/metadata/time
budgets, missing/wrong external IDs, queue leases, exception redaction, retention,
finding deduplication, unknown/absent resources and passing-check resolution.

The PostgreSQL concurrency test runs two simultaneous sessions and confirms one
active queued job. The worker heartbeat and result lease guard are implemented;
large-scale failover and multiple workers remain unsupported.

## Important limits of this evidence

The real AWS collection used an existing operator credential through the local
read-only diagnostic path. It did **not** validate a new cross-account role or
actual AWS trust-policy enforcement. Those trust tests currently use SDK doubles.
No cloud workload, volume snapshot or image download was needed.

Services with no resources can return complete inventory coverage without having
exercised every resource-detail API. GitHub live alert permissions/plan behavior,
remote TLS PostgreSQL, LDAP/OIDC/MFA, independent security review, schema upgrades,
restore rehearsals, disk exhaustion, EC2/ECS/EKS deployment, and a new Unraid VM
deployment are not claimed tested. Preview rules and exposure models intentionally
cover a subset; they are not a full Security Hub compliance implementation.

Public hosting, DNS and TLS status are recorded separately after verification.
No billed service, hosted customer signup, multi-customer SaaS security claim or
Wiz feature/price parity is implied.
