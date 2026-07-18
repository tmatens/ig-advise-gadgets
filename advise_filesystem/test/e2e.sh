#!/usr/bin/env bash
#
# End-to-end test for the advise_filesystem gadget. Runs a container that
# (a) writes to /var/lib/app/data.txt (write-intent open) and (b) only ever
# mkdir/rmdirs under /var/cache/app (metadata-only mutation — no file is opened
# for write there), and asserts the advice recommends read_only: true plus
# writable entries for BOTH directories. (b) is the regression proof for the
# security_path_* LSM-hook coverage: without it, a mkdir-only workload would be
# advised a read-only rootfs that breaks it.
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

echo "== start a container that writes a file under /var/lib/app and only mkdir/rmdirs under /var/cache/app =="
cleanup
docker run -d --name "$CONTAINER" --rm busybox:latest \
  sh -c 'mkdir -p /var/lib/app /var/cache/app; while true; do echo x > /var/lib/app/data.txt; mkdir /var/cache/app/work; rmdir /var/cache/app/work; sleep 0.2; done' >/dev/null
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
grep -q "/var/lib/app"                 <<<"$OUT" || { echo "FAIL: expected writable dir /var/lib/app (file write) not derived"; fail=1; }
grep -q "/var/cache/app"               <<<"$OUT" || { echo "FAIL: expected writable dir /var/cache/app (mkdir-only, LSM-hook path) not derived"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS: advise_filesystem recommended readOnlyRootFilesystem + writable_paths for both file writes and metadata-only mutations"
else
  echo "E2E FAILED"; exit 1
fi
