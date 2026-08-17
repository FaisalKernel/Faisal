#!/bin/sh
set -eu
OUT=${1:-/tmp/faisal-vault-dev}
mkdir -p "$OUT"
INDEX="$OUT/index.json"
curl --retry 3 --retry-delay 2 -fsSL --max-time 120 https://releases.hashicorp.com/vault/index.json -o "$INDEX"
VERSION=$(python3 - "$INDEX" <<'PY'
import json
import re
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
versions = [v for v in data["versions"] if re.fullmatch(r"\d+\.\d+\.\d+", v)]
print(sorted(versions, key=lambda v: tuple(int(x) for x in v.split('.')), reverse=True)[0])
PY
)
URL="https://releases.hashicorp.com/vault/$VERSION/vault_${VERSION}_linux_amd64.zip"
curl --retry 3 --retry-delay 2 -fL --max-time 600 "$URL" -o "$OUT/vault.zip"
unzip -oq "$OUT/vault.zip" -d "$OUT"
chmod 0755 "$OUT/vault"
printf '%s\n' "$OUT/vault"
