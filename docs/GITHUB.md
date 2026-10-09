# Optional GitHub context

Cloud scanning works without a repository connection. Repository source is not
cloned or executed by MayoCSPM.

## Existing GitHub alerts

Create a GitHub connection with `owner/repository` and a fine-grained token scoped
to that repository. Use only read permissions for code-scanning alerts, Dependabot
alerts, and repository metadata. Store the token through the authenticated HTTPS
application; it is encrypted at rest with the instance's `ENCRYPTION_KEY` and never
returned by connection responses. Back up that key separately from the database.

See GitHub's [code-scanning API](https://docs.github.com/en/rest/code-scanning/code-scanning)
and [Dependabot alert API](https://docs.github.com/en/rest/dependabot/alerts).
Availability depends on repository plan, permissions and enabled security
features. A 403/404 or unavailable product is unknown coverage, not zero risk.
The preview synchronizes existing open alerts; it does not itself cause GitHub
to run CodeQL or enable paid security products. GitHub App installation-token
rotation and PR webhooks remain planned.

Each sync reads at most six pages per category, up to 500 findings combined.
Rule IDs, alert number and a relative source location are normalized. Raw response
payloads and matched secret content are not stored. Closure synchronization for
imported alerts is not implemented; old findings remain until a reviewed closure
contract is added rather than being silently cleared after an unavailable API.

## Bring scanner reports

For self-hosted or free repository scanners, create a **SARIF** connection, then
upload SARIF 2.1.0 in the site or through its API. The request is limited to 2 MiB
including multipart overhead and 1,000 results. Run the actual scanner in your
own CI or [CheckMayo](https://github.com/quentinmayo/CheckMayo) runner; MayoCSPM does
not execute arbitrary scanner containers in its controller.

```sh
# Supply a workspace-scoped API key privately through your CI secret manager.
curl --fail --silent --show-error \
  -H "Authorization: Bearer $MAYOCSPM_API_KEY" \
  -F file=@results.sarif \
  "$MAYOCSPM_URL/api/workspaces/$WORKSPACE_ID/connections/$CONNECTION_ID/sarif"
```

PR and scheduled scanner jobs can use this import endpoint; automated GitHub App
dispatch is not implemented. Do not expose secrets to fork-PR workflows. Treat
SARIF as untrusted: messages and snippets are intentionally discarded. The
displayed finding uses the scanner's rule ID, file location and level. The
normalizer does not claim full scanner-specific severity/fingerprint support.

## Declared code-to-cloud relationships

Tag an AWS resource with `repository=owner/repository` or
`source-repo=https://github.com/owner/repository`. When the corresponding
repository resource is present in the same workspace, the graph creates a
**declared** relationship. It is based on an explicit tag, not inferred source
deployment or verified data flow. S3 tags are not collected in this preview.
