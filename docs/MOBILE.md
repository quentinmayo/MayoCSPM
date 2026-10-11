# iOS and Android apps

`mobile/` contains the Apache-2.0 Expo SDK 57 / React Native app. It connects to
an existing MayoCSPM 0.2+ instance; scanning and inventory storage stay on that
instance. Store publication and production signing are separate operator steps.
No App Store or Google Play listing is claimed.

## Available screens

| Screen | Native behavior |
| --- | --- |
| Overview | Workspace role, resource/finding counts, severity distribution, latest scans, synthetic-data label |
| Inventory | Literal name/ID search, 50-row pages, expandable configuration metadata |
| Risks | Open/accepted/resolved queue, scores, reasons, evidence and remediation |
| Exposure | First 50 observed/candidate relationships with confidence labels and limitations |
| Scans | Recent history and coverage; role-checked manual collection |
| Account | Instance, session expiry, workspace switching, logout and sign out all devices |

Use the browser for provisioning users, linking Okta, creating connections,
schedules, risk acceptance, API keys, and the graphical relationship diagram.
Viewers can read; analysts can scan already validated connections; admins/owners
can trigger initial validation. The backend enforces these boundaries regardless
of which controls a client displays. Changing/removing membership takes effect on
the next API request.

## Connect securely

Enter your instance's **HTTPS origin** without a path, then choose **Check
instance**. Sign in with a local account or **Continue with Okta** when configured.
Link Okta once in the browser before using native SSO; follow [Okta setup](OKTA.md).
The app uses the system browser rather than a password-capturing embedded webview.

The app stores only the instance, identity email, expiry, and 12-hour session token
in protected device credential storage. iOS uses a this-device-only, unlocked
keychain accessibility class; Android backups are disabled and SecureStore
exclusions are configured. Passwords, Okta secrets, and cloud inventory are not
persisted by the app. Results remain in memory while displayed; this is not an
offline client or a device-management/DLP product.

API requests omit browser cookies, use an Authorization header, reject redirects,
and time out after 15 seconds. The explicit Expo fetch transport enforces redirect rejection and streams responses
with a 2 MiB limit, including responses without Content-Length. Existing server-side query and
collection budgets remain in force. Session expiry clears local credentials;
server-side revocation is checked on each request. Logout clears the device even
if the instance is unreachable; use another device's sign-out-all action to
revoke a remote credential after an offline logout.

Native Okta handoff uses a random state, S256 PKCE, an exact custom callback
scheme, and a 60-second one-use code. The app never contains the Okta client
secret and receives no Okta access/refresh tokens. A custom scheme alone is not
exclusive ownership of a device URL handler; the PKCE proof protects an intercepted
handoff code. Verified universal/app links can replace this transport in a future
release.

## Develop and build

Install Node.js 24 LTS, then:

```sh
cd mobile
npm ci
npm run typecheck
npm run lint
npm test
npx expo-doctor
npx expo export --platform ios --platform android
```

Use SDK-compatible packages through `npx expo install`, and commit changes to
`package-lock.json`. Native directories are generated and ignored; configure them
through `app.json` and Expo config plugins.

For local development, install Xcode/CocoaPods for iOS or Android Studio, SDK and
JDK for Android. Run `npm run ios` or `npm run android` to create a development
build and start Metro. Expo Go cannot validate this app's custom SSO callback.
Development builds permit HTTP only for localhost/127.0.0.1, Android's `10.0.2.2`
host bridge, and IPv6 loopback. Release builds require HTTPS. Do not relax TLS
validation or add production cleartext exceptions to test a private server.

For cloud builds, configure your own Expo/EAS project and signing credentials:

```sh
npx eas-cli@latest build --platform android --profile preview
npx eas-cli@latest build --platform all --profile production
```

The preview profile produces an Android APK; iOS device distribution requires
Apple provisioning. Production build/upload requires the developer's Apple and
Google accounts, identifiers, signing, store metadata and privacy review. No
credentials, certificates, or keystores belong in Git. The included `eas.json`
provides profiles, not a preconfigured account or automatic submission.

If you fork the app, change the iOS bundle identifier, Android package and scheme
in `app.json`, the callback constant in `src/lib/client.ts`, and the instance's
`MOBILE_REDIRECT_URI` together, then rebuild. Do not distribute a different app
under another operator's identifiers. There is no push notification service,
background inventory collector, biometric gate, or OTA update channel configured.

## Dependency review

The lockfile pins compatible Expo versions. Overrides update `xcode`'s UUID helper
to 11.1.1 (its `v4()` API is unchanged) and `decode-uri-component` to 0.5.0 for known
advisories; native exports/builds verify compatibility.

On 2026-10-11, the latest available `braces` 3.0.3 and `node-forge` 1.4.0 still have
upstream high-severity advisories: [nested-pattern denial of service](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
and [RSA verifier ambiguity](https://github.com/advisories/GHSA-86w9-cpqp-85rv).
They are used by Metro/build tooling and Expo's code-signing tooling respectively;
the Python API does not use them and OTA updates are not enabled. Build only
reviewed source in an isolated environment. These are documented temporary
exceptions, not a clean dependency audit or a claim that the upstream flaws are
fixed. `npm run audit:review` fails for any additional advisory and expires these
exceptions on 2026-11-11; review SDK updates before then.
