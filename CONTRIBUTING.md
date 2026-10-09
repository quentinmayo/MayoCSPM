# Contributing

Use a virtual environment and the validation commands in README.md. Keep checks
small and explainable. Add meaningful regression coverage for collector bounds,
unknown results, tenant ownership, role permissions and finding lifecycles.
Use synthetic metadata for tests, screenshots and issues.

Install Gitleaks 8.30.1+ from its official releases, verify the release checksum,
and enable the local hook:

```sh
git config core.hooksPath .githooks
bash scripts/safe-commit.sh "Describe the change"
```

That command scans eligible files **before** `git add`, scans the staged index
**before** commit, and invokes the commit hook again. If staging manually, run
`bash scripts/check-secrets.sh all` before every `git add` and
`bash scripts/check-secrets.sh staged` before every commit. Never bypass hooks.
CI checks redacted secret output, Python lint/tests, dependency advisories and
image build. Keep all credentials, private profiles and real inventory outside
the checkout and build context.

Submit changes under Apache-2.0. Commercial support packaging is separate;
general engine improvements belong in this public repository. New collectors
must enumerate metadata APIs, require no data-plane access, bound pagination,
and identify missing permissions and partial scopes explicitly.
