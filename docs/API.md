# API

Swagger documentation is available at `/docs`; the OpenAPI document is
`/openapi.json`. Authentication is required on workspace endpoints.

Sign in through the site and create a workspace-scoped API key in Access & API
keys. The plaintext is shown once. Keys expire in 90 days, are stored as SHA-256
digests, and inherit the issuer's current role and membership. Revoking a key or
removing its membership immediately denies access.

```sh
# Load these values from your private secret manager; never place keys in source.
curl --fail --silent --show-error \
  -H "Authorization: Bearer $MAYOCSPM_API_KEY" \
  "$MAYOCSPM_URL/api/workspaces/$WORKSPACE_ID/resources?kind=ec2.instance&region=us-east-1"
```

| Endpoint | Purpose | Minimum role |
| --- | --- | --- |
| `GET /api/workspaces` | Workspaces accessible to this identity/key | Authenticated |
| `GET …/summary` | Resource counts, open severities, current coverage, limits | Viewer |
| `GET …/resources` | Current inventory query | Viewer |
| `GET …/findings` | Evidence-backed findings and temporary acceptances | Viewer |
| `GET …/graph` | Bounded configuration model with confidence labels | Viewer |
| `GET …/jobs` | Scan status, coverage and assessed counts | Viewer |
| `POST …/connections/{id}/scan` | Queue a scan; initial AWS validation requires admin | Analyst |
| `POST …/connections/{id}/sarif` | Import a bounded report into a SARIF connection | Analyst |
| `POST …/connections` | Create metadata/report source | Admin |
| `PUT …/connections/{id}/schedule` | Configure 0–168 hour interval | Admin |
| `POST …/findings/{id}/accept` | Accept a risk with reason and 1–90 day expiry | Admin |
| `GET/POST/DELETE …/members[/id]` | Workspace sharing and membership | Admin |
| `GET/POST/DELETE …/keys[/id]` | Create/list/revoke API keys | Admin |
| `GET …/audit` | Latest 100 workspace audit events | Admin |

`…` means `/api/workspaces/{workspace_id}`. Every child ID is checked against that
workspace; knowing an ID does not grant access. Collection queries use bound SQL
parameters. Supported resource filters are `kind`, `region`, literal substring
`q`, `tag_key`, `tag_value`, `limit` (1–200) and `offset`. The response includes
`total` and `items`. No arbitrary SQL or cloud API request is accepted.

Example tag query:

```text
/api/workspaces/1/resources?tag_key=environment&tag_value=production&limit=100
```

Findings support `status=open|accepted|resolved`, `limit`, and `offset`. An expired
acceptance appears open even before the next scan. A `partial` job can have useful
resources but is not complete security coverage. The graph includes `truncated`
and a model limitation; candidate public configurations are not reachable attack
paths. All HTTP request bodies are capped at 2 MiB.

Browser authentication uses an HttpOnly cookie, and mutations require the exact
configured Origin. API keys use the Authorization bearer header and do not need
browser CSRF headers. API responses use `Cache-Control: no-store`. Do not pass
credentials in URLs or query strings.
