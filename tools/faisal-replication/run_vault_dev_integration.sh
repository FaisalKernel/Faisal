#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
IMAGE=${VAULT_DEV_IMAGE:-}
NAME=${VAULT_DEV_NAME:-faisal-vault-dev}
PORT=${VAULT_DEV_PORT:-18200}
TOKEN=${VAULT_DEV_TOKEN:-faisal-local-dev-token}
if ! command -v docker >/dev/null 2>&1; then
  echo FJT_VAULT_CONTAINER_UNAVAILABLE >&2
  exit 77
fi
if [ -z "$IMAGE" ]; then
  echo 'VAULT_DEV_IMAGE must be pinned by the operator, for example hashicorp/vault:<verified-version>' >&2
  exit 77
fi
cleanup() {
  set +e
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
docker run -d --rm --name "$NAME" -p "$PORT":8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID="$TOKEN" \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  "$IMAGE" server -dev >/tmp/faisal-vault-container.log 2>&1
for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -fsS -H "X-Vault-Token: $TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"type":"ed25519"}' \
  "http://127.0.0.1:$PORT/v1/transit/keys/faisal-journal" >/dev/null
curl -fsS -H "X-Vault-Token: $TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"input":"am91cm5hbC1hdHRlc3RhdGlvbg=="}' \
  "http://127.0.0.1:$PORT/v1/transit/sign/faisal-journal" >/tmp/faisal-vault-sign-response.json
python3 - "$ROOT/tools/faisal-journal-trust/faisal_remote_kms_client.py" <<'PY'
import json
import sys
with open('/tmp/faisal-vault-sign-response.json', encoding='utf-8') as handle:
    data = json.load(handle)
signature = data.get('data', {}).get('signature', '')
if not signature.startswith('vault:v'):
    raise SystemExit('Vault Transit response lacks versioned signature')
print('FJT_VAULT_DEV_CONTAINER_SIGN_OK')
PY
