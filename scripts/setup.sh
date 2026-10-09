#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Install Docker Engine and the Compose plugin from https://docs.docker.com/engine/install/ first.'; exit 1; }
docker compose version >/dev/null
if [[ ! -f .env ]]; then
  command -v python3 >/dev/null || { echo 'Install Python 3 for private configuration generation.'; exit 1; }
  read -r -p 'Administrator email: ' MAYOCSPM_SETUP_EMAIL
  export MAYOCSPM_SETUP_EMAIL
  python3 - <<'PY'
import base64, os, re, secrets
from pathlib import Path
email=os.environ['MAYOCSPM_SETUP_EMAIL'].strip().lower()
if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or any(c in email for c in "\"'#$\\"):
    raise SystemExit('Invalid administrator email')
password=secrets.token_urlsafe(24)
key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
env=f'PUBLIC_URL=http://localhost:8010\nMAYOCSPM_PORT=8010\nBOOTSTRAP_EMAIL={email}\nBOOTSTRAP_PASSWORD={password}\nPOSTGRES_PASSWORD={secrets.token_urlsafe(32)}\nENCRYPTION_KEY={key}\nAWS_REGION=us-east-1\nAWS_EC2_METADATA_DISABLED=true\n'
with open('.env','x') as f: f.write(env)
os.chmod('.env',0o600)
print('Private configuration created in .env. Read BOOTSTRAP_PASSWORD there; it is not printed or logged.')
PY
else
  echo 'Reusing existing private .env; database and credentials are preserved.'
fi
docker compose up -d --build --wait
echo 'Ready at the PUBLIC_URL configured in .env (default http://localhost:8010).'
echo 'Back up the database and ENCRYPTION_KEY separately. Add a demo connection to explore without AWS access.'
