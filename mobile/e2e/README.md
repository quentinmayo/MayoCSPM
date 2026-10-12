# Native viewer regression check

Run `viewer.yaml` with Maestro against a **dedicated synthetic test workspace**
with the five-resource/seven-finding demo connection already scanned. Provision
a temporary viewer with local password sign-in enabled. Start with the app signed
out, and supply `MAESTRO_MAYOCSPM_QA_URL`, `MAESTRO_MAYOCSPM_QA_EMAIL` and
`MAESTRO_MAYOCSPM_QA_PASSWORD` through your process environment, loaded from a private
credential file. Do not put credentials in YAML or command-line arguments.

```sh
umask 077
MAESTRO_CLI_NO_ANALYTICS=1 maestro --udid YOUR_TEST_DEVICE_ID test \
  mobile/e2e/viewer.yaml --test-output-dir /private/test-results
```

Run separately on an Android emulator and iOS simulator with a Release build
installed. Use your own output directory and explicitly select the test device.
Maestro logs can include entered credentials; keep all debug artifacts private.
Revoke and remove the temporary account after testing.

The flow checks login, workspace identity, inventory inspection, risk evidence,
exposure labels, hidden viewer scan controls, protected-storage persistence after
process restart, sign-out-all returning to sign-in, and a cold custom callback
with dummy credentials that must not authenticate. API tests separately verify
server-side viewer write denial and token revocation. This flow does not validate
a real Okta tenant, provider MFA, production signing or physical-device behavior.
