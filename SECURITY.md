# Security policy

This early preview is not a substitute for a complete cloud security program or
independent assessment. Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/quentinmayo/MayoCSPM/security/advisories/new).
Do not post credentials, cloud account inventories, customer findings or source
snippets in public issues.

The app is designed for self-hosting with bounded metadata collection. Use TLS,
restrict administrator access, keep API keys in a secret manager, and isolate
the worker's operator identity. The read-only collector role contains no snapshot,
object-read, image-download, secret-value or cloud mutation permissions.

Runtime resource limits do not enforce a filesystem quota. Configure one and
monitor backups, WAL and free space. Encrypt backups and retain the token
encryption key separately. Use the single-app/single-worker preview topology.

Workspace authorization is enforced by application queries; database RLS,
enterprise SSO/MFA, automated restore/upgrade handling and an external review
remain future work. See [architecture](docs/ARCHITECTURE.md) and
[validation](docs/VALIDATION.md) for the exact tested scope.

Before staging or committing, run the secret scans described in CONTRIBUTING.md.
Gitleaks reduces accidental leakage; it is not proof that arbitrary private
material is safe to publish. Real cloud inventory is never a fixture for screenshots.
