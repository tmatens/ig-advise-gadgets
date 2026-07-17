#!/usr/bin/env bash
#
# End-to-end test for the advise_devices gadget. Runs a container that opens a
# non-default device node (/dev/fuse) and asserts the advice lists it in a
# devices: grant while excluding default nodes like /dev/null.
#
# Requires root (ig loads eBPF; OCI store under /var/lib/ig) and a host /dev/fuse.
#   sudo IG=/path/to/ig bash gadgets/advise_devices/test/e2e.sh
set -euo pipefail

IG="${IG:-ig}"
GADGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="advise_devices:e2e"
CONTAINER="advise-dev-e2e"
DURATION="${DURATION:-8}"
DEVICE="${DEVICE:-/dev/fuse}"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo -n"; fi

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [ ! -e "$DEVICE" ]; then
  echo "SKIP: $DEVICE not present on host (set DEVICE= to another non-default node)"; exit 0
fi

echo "== build gadget =="
$SUDO "$IG" image build "$GADGET_DIR" -t "$IMAGE"

echo "== start a container that opens $DEVICE =="
cleanup
docker run -d --name "$CONTAINER" --rm --device "$DEVICE:$DEVICE" busybox:latest \
  sh -c "while true; do cat $DEVICE >/dev/null 2>&1; sleep 0.2; done" >/dev/null
sleep 1

echo "== run advise_devices for ${DURATION}s =="
OUT="$($SUDO "$IG" run "$IMAGE" \
  --verify-image=false --pull never \
  --containername "$CONTAINER" --timeout "$DURATION" 2>/dev/null || true)"
echo "---- gadget output ----"
echo "$OUT"
echo "-----------------------"

echo "== assertions =="
fail=0
grep -q "device_nodes:" <<<"$OUT" || { echo "FAIL: no device_nodes list emitted"; fail=1; }
grep -q "$DEVICE"       <<<"$OUT" || { echo "FAIL: expected $DEVICE in list"; fail=1; }
grep -q "/dev/null"     <<<"$OUT" && { echo "FAIL: default node /dev/null leaked into list"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS: advise_devices listed $DEVICE and excluded default nodes"
else
  echo "E2E FAILED"; exit 1
fi
