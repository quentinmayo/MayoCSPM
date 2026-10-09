# MayoCSPM

This is a public, Apache-2.0 project. Do not copy private operational configuration,
customer inventories, proprietary code, credentials or internal hostnames here.

Before **every** staging operation run `bash scripts/check-secrets.sh all`.
Before **every** commit run `bash scripts/check-secrets.sh staged`.
Use `scripts/safe-commit.sh` with gitleaks on PATH. Never bypass hooks.

Keep AWS collection read-only. API connections use STS roles, never persistent
access keys. Treat incomplete collection as unknown; never resolve findings merely
because a collector failed or a resource disappeared. Every object lookup and
mutation must include its workspace. Add regression tests for security boundaries.

This is an early preview. Document verified coverage and missing capabilities
accurately. Risk relationships are configuration-based candidates, not proof of
exploitation. Do not claim Wiz parity or certified compliance.
