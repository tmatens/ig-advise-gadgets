#!/usr/bin/env bash
#
# End-to-end test for the advise_capabilities gadget. A container exercising
# CAP_CHOWN must yield a k8s securityContext that drops ALL and adds exactly the
# capabilities the workload used (CHOWN) — no runtime-setup caps.
#
# On runtime-setup noise: under --containername (exercised here) ig's own
# container-registration boundary already excludes the runtime's setup caps, so
# the derived set is workload-minimal without any comm-based filter. This test
# asserts that minimality (add CHOWN; no setup caps like SYS_ADMIN/MKNOD). See
# the design note in ../README.md.
#
# ig loads eBPF and writes the OCI store under /var/lib/ig, so ig calls need
# root. Run as root, or with passwordless sudo scoped to the ig binary.
set -euo pipefail

IG="${IG:-ig}"
GADGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="advise_capabilities:e2e"
CONTAINER="advise-caps-e2e"
DURATION="${DURATION:-8}"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo -n"; fi

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== build gadget =="
$SUDO "$IG" image build "$GADGET_DIR" -t "$IMAGE"

echo "== start a container that exercises CAP_CHOWN in a loop =="
cleanup
docker run -d --name "$CONTAINER" --rm busybox:latest \
  sh -c 'touch /tmp/f; while true; do chown 1:1 /tmp/f; chown 0:0 /tmp/f; sleep 0.2; done' >/dev/null
sleep 1

echo "== run advise_capabilities for ${DURATION}s =="
OUT="$($SUDO "$IG" run "$IMAGE" \
  --verify-image=false --pull never \
  --containername "$CONTAINER" --timeout "$DURATION" 2>/dev/null || true)"
echo "---- gadget output ----"
echo "$OUT"
echo "-----------------------"

echo "== assertions =="
fail=0
grep -q "securityContext:"          <<<"$OUT" || { echo "FAIL: not a k8s securityContext block"; fail=1; }
grep -Eq "drop:\s*$"                 <<<"$OUT" || { echo "FAIL: no drop: list"; fail=1; }
grep -qw "ALL"                       <<<"$OUT" || { echo "FAIL: drop is not ALL"; fail=1; }
grep -qw "CHOWN"                     <<<"$OUT" || { echo "FAIL: expected workload cap CHOWN not recommended"; fail=1; }
# workload-minimal: runtime-setup caps the busybox workload never uses must not leak.
grep -qw "SYS_ADMIN"                 <<<"$OUT" && { echo "FAIL: SYS_ADMIN leaked (setup cap, never used by workload)"; fail=1; }
grep -qw "MKNOD"                     <<<"$OUT" && { echo "FAIL: MKNOD leaked (setup cap, never used by workload)"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS: workload-minimal k8s securityContext (drop ALL, add CHOWN, no setup caps)"
else
  echo "E2E FAILED"; exit 1
fi
