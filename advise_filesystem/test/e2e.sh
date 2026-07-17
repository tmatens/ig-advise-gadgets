#!/usr/bin/env bash
#
# End-to-end test for the advise_filesystem gadget. Runs a container that writes
# to /var/lib/app/data.txt and asserts the advice recommends read_only: true
# plus a tmpfs entry for the directory it wrote to.
#
# ig loads eBPF and writes the OCI store under /var/lib/ig, so the ig calls need
# root. Run as root (sudo IG=/path/to/ig bash e2e.sh) or, with passwordless sudo
# scoped to the ig binary, run as your user and the script sudoes the ig calls.
set -euo pipefail

IG="${IG:-ig}"
GADGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="advise_filesystem:e2e"
CONTAINER="advise-fs-e2e"
DURATION="${DURATION:-8}"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo -n"; fi

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== build gadget =="
$SUDO "$IG" image build "$GADGET_DIR" -t "$IMAGE"

echo "== start a container that writes a file under /var/lib/app =="
cleanup
docker run -d --name "$CONTAINER" --rm busybox:latest \
  sh -c 'mkdir -p /var/lib/app; while true; do echo x > /var/lib/app/data.txt; sleep 0.2; done' >/dev/null
sleep 1

echo "== run advise_filesystem for ${DURATION}s =="
OUT="$($SUDO "$IG" run "$IMAGE" \
  --verify-image=false --pull never \
  --containername "$CONTAINER" --timeout "$DURATION" 2>/dev/null || true)"
echo "---- gadget output ----"
echo "$OUT"
echo "-----------------------"

echo "== assertions =="
fail=0
grep -q "readOnlyRootFilesystem: true" <<<"$OUT" || { echo "FAIL: no readOnlyRootFilesystem baseline"; fail=1; }
grep -q "writable_paths:"              <<<"$OUT" || { echo "FAIL: no writable_paths block"; fail=1; }
grep -q "/var/lib/app"                 <<<"$OUT" || { echo "FAIL: expected writable dir /var/lib/app not derived"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS: advise_filesystem recommended readOnlyRootFilesystem + writable_paths /var/lib/app"
else
  echo "E2E FAILED"; exit 1
fi
