# Okta sign-in

The 0.2 preview supports Okta OpenID Connect for the browser and native apps.
Okta authenticates a linked identity; MayoCSPM applies its existing workspace
memberships on every request. There is no public signup, automatic email linking,
Okta group-to-role mapping, SAML, SCIM provisioning, or directory synchronization.

## Configure an instance

Use a trusted HTTPS reverse proxy and set `PUBLIC_URL` to its exact origin,
for example `https://cloud.example.com`. Paths and HTTP origins are rejected when
OIDC is enabled. Preserve the existing encryption key and back up PostgreSQL.

In the Okta Admin Console, create an **OIDC / Web Application** integration with
Authorization Code enabled, client-secret basic authentication, and this exact
sign-in redirect URI:

```text
https://cloud.example.com/api/auth/oidc/callback
```

Assign the intended people to the Okta application. Copy the issuer from your
Okta authorization server's discovery settings; both the organization issuer
(`https://example.okta.com`) and a configured custom authorization server issuer
(`https://example.okta.com/oauth2/default`) can be used. Confirm your tenant's
entitlements before choosing a custom authorization server. Discovery,
authorization, token, and signing-key endpoints must share the configured HTTPS
issuer origin. The integration requests `openid email profile` and validates
RS256 ID tokens; no Okta administrator API token is needed.

Set these values in the instance's private `.env` or deployment secret manager:

```dotenv
PUBLIC_URL=https://cloud.example.com
OIDC_ISSUER=https://example.okta.com
OIDC_CLIENT_ID=your-web-application-client-id
OIDC_CLIENT_SECRET=your-private-client-secret
PASSWORD_LOGIN_ENABLED=true
MOBILE_REDIRECT_URI=com.quentinmayo.mayocspm://auth
```

Keep reverse-proxy logs from retaining authorization query strings or credential
headers. Keep the existing `ENCRYPTION_KEY`. Never put the client secret in mobile source,
GitHub, screenshots, or a support issue. Compose passes OIDC secrets only to the
API app; the collector worker does not need them. Recreate the app after changing
its environment (`docker compose up -d app`). Partial configuration fails startup
instead of silently disabling authentication.

The same server-side Web Application handles mobile sign-in. **Do not register the
native custom scheme as an Okta redirect URI**: Okta returns to the HTTPS server
callback; the server returns a short-lived handoff code to the app. A separately
registered Okta native client is not required for this bridge.

## Link existing users

1. An owner/admin provisions the person's local account and workspace role.
2. That person signs in with their existing password in the browser and opens
   **Sign-in & devices → Link Okta**, confirming their current password.
3. They complete Okta sign-in. Okta must return a verified email matching this
   account for this initial link. The issuer and subject are then bound to the
   local user; later logins use that binding rather than an email match.
4. Test **Continue with Okta** in a separate browser session and the mobile app.
   Verify both permitted and forbidden workspace actions for each assigned role.

An unlinked identity receives a generic failed-sign-in result even if its email
matches an owner. Group claims cannot grant owner/admin access. Identity linking
is a global account setting, so workspace API keys cannot perform it or revoke
all of a user's sessions.

## Enforce your Okta policy

Configure MFA and application sign-on policy in Okta. Local password login
bypasses the IdP policy while enabled. After **every required user has linked and
tested their identity**, operators can set `PASSWORD_LOGIN_ENABLED=false` and
recreate the API app. Startup refuses this setting without OIDC configuration.

This flag blocks new browser/mobile password logins; it does not invalidate
already issued sessions or workspace API keys. Use **Sign out all devices** to
revoke the user's browser/mobile sessions, and manage API keys separately. Keep
an operator recovery procedure outside Git: an operator with deployment access
can restore the flag during an IdP outage. Password recovery and an interactive
break-glass console are not implemented.

## Session and protocol boundaries

- Authorization Code with S256 PKCE, state, nonce, and a Secure/HttpOnly browser
  binding cookie; five-minute, single-use database-backed authorization flows.
- Exact issuer/audience, authorized party, nonce, signature, and expiry checks;
  RSA keys must be at least 2048 bits. Provider responses are capped at 64 KiB.
- The native app adds its own PKCE proof. Its opaque, one-use handoff code expires
  in 60 seconds. Bearer tokens and IdP tokens never enter a redirect URL.
- Browser and mobile credentials expire after 12 hours and are stored as hashes
  on the instance. No refresh token or upstream Okta token is persisted.
- Logout is local. It does not terminate the system browser's Okta session.
  Disabling an Okta user does not immediately revoke existing MayoCSPM sessions;
  revoke local sessions or remove workspace membership for immediate denial.
- Unlinking requires the current password and enabled password login. It prevents
  future Okta logins but does not revoke existing sessions; revoke them separately.
- Pending flows are capped at 200 per instance; expired entries are pruned on the
  next authorization start. This is not a distributed identity-rate limiter.

Automated tests use an RSA-signed provider fixture, not a real Okta tenant. Real
assignment, MFA, custom-domain, outage and group-policy behavior require an
operator's tenant validation before rollout. See [validation](VALIDATION.md).

References: [Okta web redirect integration](https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/)
and [authorization servers](https://developer.okta.com/docs/concepts/auth-servers/).
