# Roadmap

The preview is intentionally configuration-only and resource-bounded. Its core
inventory/query/exposure contract stays available in the Apache-2.0 engine.

## Next reliability work

- Real cross-account role onboarding and negative trust tests against AWS.
- Dedicated filesystem quota and free-space admission checks; measured per-scan
  and per-workspace storage accounting.
- Restore rehearsals, schema migrations, dependency lock/hashes, signed releases
  and image digests.
- Connection editing/deletion, account recovery and explicit data lifecycle tools.
- Collector coverage matrix, missing-field/region tests and long-running failures.
- Worker health reporting, retry budgets and reviewed multi-worker scheduling.

## Better cloud context

- Subnets, route tables, gateways, NACLs and load balancers, within selected scopes.
- IAM role/policy metadata with explicit, conservative entitlement modeling.
- Serverless and ECR **repository metadata** where useful, without downloading
  layers or creating workload snapshots.
- More query operators and saved queries, with cost/row limits.
- Per-source freshness and export reports, without calling uncertainty a pass.
- More original posture rules and reviewed control mappings; no certification
  claims without independent validation.

## Optional application context

- A user-owned GitHub App, narrow permissions and installation-token rotation.
- Signed/replay-protected PR webhook dispatch to isolated CheckMayo runners.
- Reviewed closure semantics and scanner-specific SARIF fingerprints/severity.
- Explicit deployment provenance and code-to-cloud links.

## Identity and ecosystem

- OIDC/OAuth, LDAPS, MFA and recovery; access-matrix and tenant-boundary tests.
- Restricted OPA/Rego risk policies with resource limits and no network builtins.
- Additional clouds and Kubernetes posture after AWS coverage is dependable.
- Optional, explicitly enabled AI summaries with an operator-chosen local model.

## Commercial direction

[Mayo CSPM](https://mayocspm.com) can offer deployment help, supported upgrades and
managed operations. Commercial billing, pricing and hosted customer signup are
not launched. The software's free license does not remove host, API, backup,
network or support costs. A cost model should precede published savings claims.
