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
| `GET …/graph/context` | Evidence neighborhood; `node_id`, `direction=in\|out\|both`, `depth=1..4` | Viewer |
| `GET …/query/schema` | MQL entities, relationships, examples and limits | Viewer |
| `POST …/query` | Execute `{expression}` against bounded stored graph | Viewer |
| `GET …/queries` | Workspace shared queries | Viewer |
| `POST/PUT/DELETE …/queries[/id]` | Save/update `{name, expression}` or delete; cap 50 | Analyst |
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

## Browser and native identity

`GET /api/auth/options` publicly reports enabled login methods and the fixed
native callback URI; it does not expose client secrets. [Okta setup](OKTA.md)
describes the server configuration and explicit account linking.

| Endpoint | Purpose | Authentication |
| --- | --- | --- |
| `POST /api/auth/login` | Email/password browser session cookie | Public; exact Origin; password login enabled |
| `POST /api/auth/mobile/login` | Email/password native bearer session | Public; rate limited; password login enabled |
| `GET /api/auth/oidc/start` | Begin browser authorization; optional native `code_challenge` + `state` | Public; OIDC configured |
| `GET /api/auth/oidc/callback` | Provider return; binding/state/PKCE/ID-token validation | One-use flow and binding cookie |
| `POST /api/auth/mobile/exchange` | Exchange `{code, verifier}` for a native session | One-use handoff and PKCE proof |
| `GET /api/auth/oidc/account` | Enabled/linked account settings | Browser/mobile session; not a workspace API key |
| `POST /api/auth/oidc/link` | Explicitly bind Okta; body `{password}` | Browser session + exact Origin + current password |
| `DELETE /api/auth/oidc/account` | Remove binding; body `{password}` | Same; password login must remain enabled |
| `POST /api/auth/logout` | Revoke current credential | Current session/key; cookie mutations require Origin |
| `POST /api/auth/sessions/revoke` | Revoke all current user's browser/mobile sessions | Browser/mobile session; API keys remain separate |

Native login/exchange return `{token, expires_at, email}` without a cookie. Use the
token only in the Authorization bearer header. It expires after 12 hours and
inherits the user's current memberships; it is not a scoped 90-day automation
key. Passwords and IdP tokens are not returned. MFA policy is enforced by Okta
only when users sign in through it; local passwords can be disabled after links
are verified. IdP logout and immediate IdP-driven local revocation are not implemented.

## Graph query API

Send `POST /api/workspaces/{id}/query` with a JSON `expression`, for example
`MATCH (r:Resource) WHERE r.exposure = "potential" RETURN r LIMIT 100`.
The response includes columns/rows, matched graph, coverage, warnings, truncation,
counts completeness and execution statistics. A 422 identifies syntax/grammar
errors without echoing the full submitted query. A 503 indicates graph concurrency
admission or a database timeout; retry rather than sending parallel queries.
Browser query POSTs require exact Origin despite being read-only. See
[the language contract](QUERY-LANGUAGE.md) and [graph semantics](EXPOSURE-GRAPH.md).
