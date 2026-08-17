#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
TMP=${TMPDIR:-/tmp}/faisal-live-partition-$$
mkdir -p "$TMP"
cleanup() {
  set +e
  [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null
  sudo iptables -D OUTPUT -o lo -p tcp --dport 19443 -j DROP 2>/dev/null || true
  sudo iptables -D OUTPUT -o lo -p tcp --sport 19443 -j DROP 2>/dev/null || true
  sudo iptables -D INPUT -i lo -p tcp --dport 19443 -j DROP 2>/dev/null || true
  sudo iptables -D INPUT -i lo -p tcp --sport 19443 -j DROP 2>/dev/null || true
  sudo tc qdisc del dev lo root 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost -keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1
cp "$TMP/cert.pem" "$TMP/ca.pem"
READY="$TMP/ready"
GO="$TMP/go"
RELEASE="$TMP/release"
python3 "$ROOT/tools/faisal-replication/live_partition_fault_test.py" \
  --port-a 19443 --port-b 19444 --cert "$TMP/cert.pem" --key "$TMP/key.pem" \
  --ca "$TMP/ca.pem" --ready-file "$READY" --go-file "$GO" --release-file "$RELEASE" >"$TMP/output" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
  [ -e "$READY" ] && break
  kill -0 "$PID" 2>/dev/null || { cat "$TMP/output"; exit 1; }
  sleep 0.05
done
[ -e "$READY" ] || { cat "$TMP/output"; echo FJT_LIVE_PARTITION_SETUP_TIMEOUT; exit 1; }
sudo iptables -I OUTPUT -o lo -p tcp --dport 19443 -j DROP
sudo iptables -I OUTPUT -o lo -p tcp --sport 19443 -j DROP
sudo iptables -I INPUT -i lo -p tcp --dport 19443 -j DROP
sudo iptables -I INPUT -i lo -p tcp --sport 19443 -j DROP
: > "$GO"
for _ in $(seq 1 120); do
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.05
done
sudo iptables -D OUTPUT -o lo -p tcp --dport 19443 -j DROP
sudo iptables -D OUTPUT -o lo -p tcp --sport 19443 -j DROP
sudo iptables -D INPUT -i lo -p tcp --dport 19443 -j DROP
sudo iptables -D INPUT -i lo -p tcp --sport 19443 -j DROP
: > "$RELEASE"
set +e
wait "$PID"
rc=$?
set -e
cat "$TMP/output"
[ "$rc" -eq 0 ] || exit "$rc"
echo FJT_LIVE_SOCKET_PARTITION_QEMU_HOST_VALIDATION_OK
