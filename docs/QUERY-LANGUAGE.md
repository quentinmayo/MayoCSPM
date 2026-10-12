# Query your cloud with MQL / 1

Open **Query explorer** in the authenticated console. Choose a question, edit the
query, and run it with the button or Ctrl/⌘ + Enter. Results include a table and
an interactive graph of the matched entities and relationships. A small builder
creates resource/risk queries with type, tag, score and public-configuration filters.
Analysts and administrators can maintain up to 50 shared queries per workspace;
viewers can run them. Queries use stored observations and never call AWS.

MQL is MayoCSPM's original, read-only language. It is not Wiz query compatibility,
SQL, unrestricted Cypher, a shell, or a remote provider query. The parser accepts
only the documented grammar. These examples run against the bundled synthetic
connection; some require additional collected relationships.

## Start with a question

Find resources whose observed public configuration deserves review:

```text
MATCH (r:Resource)
WHERE r.exposure = "potential"
RETURN r
LIMIT 100
```

Find workloads attached to security groups with high or critical open findings:

```text
MATCH (g:Resource)-[:SECURITY_GROUP_ATTACHED]->(r:Resource),
      (g)-[:HAS_FINDING]->(f:Finding)
WHERE f.status = "open" AND f.severity IN ["high", "critical"]
RETURN g, r, f
ORDER BY f.score DESC
LIMIT 100
```

Follow a candidate Internet configuration through a workload to its EBS volume:

```text
MATCH p=(i:Internet)-[:PUBLIC_CONFIGURATION|SECURITY_GROUP_ATTACHED|USES_VOLUME*1..3]->(r:Resource)
WHERE r.kind = "ec2.volume"
RETURN p, r
LIMIT 50
```

This is a chain of configuration evidence, **not proof of a usable attack path**.
A group reference does not establish transitive network access. Review the
[evidence model and its gaps](EXPOSURE-GRAPH.md) before interpreting a path.

Find services configured to write logs to a bucket:

```text
MATCH (service:Resource)-[:LOGS_TO]->(bucket:Resource)
WHERE bucket.kind = "s3.bucket" AND bucket.name = "example-demo-reports"
RETURN service, bucket
```

Currently `LOGS_TO` covers CloudTrail destinations. It does not infer every
application that reads/writes a bucket. Missing relationships are missing evidence.

Filter production tags and count open findings by severity:

```text
MATCH (r:Resource)-[:HAS_FINDING]->(f:Finding)
WHERE r.data.tags["environment"] IN ["production", "prod"] AND f.status = "open"
RETURN f.severity AS severity, COUNT(*) AS findings, COUNT(DISTINCT r) AS resources
ORDER BY findings DESC
```

## Entities and joins

| Entity | Useful properties |
| --- | --- |
| `Resource` | `id`, `resource_id`, `connection_id`, `uid`, `name`, `kind`, `region`, `seen`, `data`, `exposure`, `exposure_evidence`, `limitations`, `finding_count` |
| `Finding` | `id`, `finding_id`, `connection_id`, `resource_uid`, `name`, `severity`, `score`, `status`, `check_id`, `last_seen`, `resource_current`, `evidence`, `remediation` |
| `Connection` | `id`, `connection_id`, `name`, `kind`, `validated` |
| `Internet` | `id`, `name`, `kind`, `exposure` |

`GET /api/workspaces/{id}/query/schema` supplies all allowed properties, operators,
relationships, limits and example queries. Connection secrets, role configuration,
external IDs, users and credentials are never queryable.

A resource ID includes its connection so equal AWS resource IDs from two sources
cannot collide. Relationships stay within the source unless an explicit repository
tag declares a code-to-cloud association. Resources come from each connection's
latest snapshot; findings include retained historical records. `resource_current`
is `false` when the resource is absent from a complete bounded selection, and
`null` when a resource limit prevents that determination. Old findings are not
resolved by disappearing resources or incomplete collection. Expired acceptances
are evaluated as open at query time.

Declare an alias with `(r:Resource)`. Reuse it as `(r)` in another pattern to join
on the same entity. Comma-separated patterns must share a node alias; up to three
patterns are allowed. Disconnected Cartesian products and cycles within one
pattern are rejected. Multiple AWS and repository connections in the **same
workspace** participate; queries cannot cross workspace boundaries.

## Relationship syntax

| Form | Meaning |
| --- | --- |
| `(a:Resource)-[:USES_VOLUME]->(b:Resource)` | Follow outgoing relationships |
| `(a:Resource)<-[:USES_VOLUME]-(b:Resource)` | Follow incoming relationships |
| `(a:Resource)-[:USES_VOLUME]-(b:Resource)` | Either direction |
| `(a:Resource)-->(b:Resource)` | Any outgoing relationship type |
| `(a:Resource)-[e:USES_VOLUME]->(b:Resource)` | Return/filter a single edge alias |
| `p=(a:Internet)-[:PUBLIC_CONFIGURATION\|SECURITY_GROUP_ATTACHED*1..3]->(b:Resource)` | Bind a path, following either type for 1–3 hops |

Relationship names are listed in [the graph guide](EXPOSURE-GRAPH.md). Every edge
has `source`, `target`, `type`, `confidence`, `evidence` and `limitations`. `RETURN e`
includes these fields. `RETURN p` includes ordered node summaries, edges and
`length`; `p.length` is filterable. Variable paths require an explicit range of
1–4 hops, use simple paths without repeated nodes, and cannot bind a single edge
alias. A pattern's total maximum length is four hops.

## Filters, projection and aggregation

Keywords and entity/relationship types are case-insensitive; aliases, property
names and string values are case-sensitive. Strings require JSON double quotes
and JSON escapes. Values may be strings, numbers, booleans or null.

- Comparisons: `=`, `!=`, `<`, `<=`, `>`, `>=`. Boolean and numeric types are distinct.
- Membership: `IN [...]`, `NOT IN [...]`, up to 50 scalar values.
- Text/list: `CONTAINS` (text or scalar list member), `ICONTAINS` (case-insensitive
  text), `STARTS WITH`, `ENDS WITH`. No user-supplied regular expressions.
- Boolean: `NOT`, `AND`, `OR`, parentheses. AND takes precedence over OR.
- Missing evidence: `IS NULL`, `IS NOT NULL`. Comparisons against unavailable
  values evaluate to **unknown**, including `!=` and negation; only true rows
  match. For example, `NOT r.data.encrypted = true` does not label missing
  encryption metadata as unencrypted. Use `r.data.encrypted IS NULL` explicitly.
- Property paths: `r.data.tags.environment`, `r.data.tags["source-repo"]`,
  `r.data.security_groups[0]`, at most eight components.
- `RETURN` selects aliases/properties, with optional `AS` names; `DISTINCT`
  removes duplicate projected rows. Whole entities return summaries. Select
  `r.data`, `f.evidence` or `f.remediation` explicitly for detailed metadata.
- `COUNT(*)`, `COUNT(f.score)`, `COUNT(DISTINCT r)` support grouping by the other
  returned columns. Property counts exclude nulls. An empty complete input
  returns zero for an ungrouped count; incomplete input is explicitly partial.
- `ORDER BY` sorts returned columns or their object properties, with `ASC`/`DESC`;
  null values sort last. Use `AS` for bracketed property paths. At most three sort
  keys. `LIMIT` is 1–200, default 100. No offset or cursor in MQL / 1.

## Cost, freshness and partial answers

Every result includes `coverage`, `warnings`, `truncated`, `counts_complete`,
`matched_rows_observed`, `has_more`, limits and duration. `has_more` describes
observed rows beyond LIMIT; it is not an inventory completeness guarantee. Counts
are lower bounds whenever `counts_complete` is false. A partial empty answer
must never be interpreted as no risk. Even a complete query describes only the
supported, collected metadata, with scan timestamps shown per source.

Admission is capped at 1,000 current resources, 2,000 findings, 10,000 edges and
4 MiB of conservatively charged JSON metadata. Metadata fields above 65,536 SQL
characters are skipped before JSON loading and remain unknown. Execution stops
at 25,000 traversal operations, 5,000 intermediate matches, 2 MiB of intermediate
projection accounting or a cooperative two-second evaluation deadline, checked
between operations. PostgreSQL statements have a two-second timeout; SQLite uses
a progress deadline. These are not a hard two-second HTTP wall-time guarantee:
JSON decoding/serialization and response delivery add time.

Only two graph/query reads run concurrently per API process; excess work receives
503 with Retry-After instead of accumulating in a work queue. Result rows have a
512 KiB budget; matched graphs are limited to 100 nodes, 200 edges and 384 KiB.
Skipped data and graphs retain warnings and never return orphan edges. See the
[full data budget](DATA-BUDGET.md). There is no export-all or unbounded traversal.

Saved queries store their text in the workspace database; do not put credentials
or sensitive literals in queries. Audit events record saved-query IDs and actions,
not query text. Browser POST requests require the exact configured Origin even
when the operation is read-only. API keys keep their existing scope and role.
