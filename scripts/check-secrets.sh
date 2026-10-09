#!/usr/bin/env bash
set -euo pipefail
if ! command -v gitleaks >/dev/null; then
  echo 'Install gitleaks 8.30.1+ before staging or committing. No scan was performed.' >&2
  exit 1
fi
CHECKMAYO_SCAN_DIR="$(mktemp -d)"
trap 'rm -rf "$CHECKMAYO_SCAN_DIR"' EXIT
export CHECKMAYO_SCAN_DIR
python3 - "${1:-all}" <<'PY'
import os, subprocess, sys
from pathlib import Path
mode=sys.argv[1]
root=Path(os.environ['CHECKMAYO_SCAN_DIR'])
if mode=='staged':
 names=subprocess.check_output(['git','diff','--cached','--name-only','--diff-filter=ACMR','-z']).split(b'\0')
else:
 names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).split(b'\0')
for raw in names:
 if not raw:continue
 name=raw.decode();source=Path(name)
 if source.is_absolute() or '..' in source.parts:raise SystemExit('Unsafe filename')
 if source.is_symlink():raise SystemExit('Publication candidates may not be symlinks')
 if mode=='staged':content=subprocess.check_output(['git','show',':'+name])
 elif source.is_file():content=source.read_bytes()
 else:continue
 if source.suffix in ('.pem','.key','.enc','.db') or source.name=='.env':raise SystemExit('Sensitive file type cannot be published')
 target=root/source;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
PY
gitleaks dir "$CHECKMAYO_SCAN_DIR" --redact --no-banner --exit-code 1
