#!/bin/sh
# Execute the real three-node gRPC/mTLS software qualification fixture.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${FAISAL_REPLICATION_FIXTURE_OUT:-$ROOT/../build/m171-replication}
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-replication${PYTHONPATH:+:$PYTHONPATH}"
export FAISAL_REPLICATION_SOURCE_REV="${FAISAL_REPLICATION_SOURCE_REV:-$(git -C "$ROOT" rev-parse HEAD)}"
export FAISAL_REPLICATION_REVIEWED_EPOCH="${FAISAL_REPLICATION_REVIEWED_EPOCH:-$(date +%s)}"
exec python3 "$ROOT/tools/faisal-replication/full_tls_replication_fixture.py" \
  --result "$OUT/full-tls-replication-fixture.json"
