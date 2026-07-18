# advise_devices — internals

A function-by-function walkthrough of how the gadget works. The
[`README.md`](README.md) covers *what* it is and how to run it; this document
covers *how* it works and *why* each piece is the way it is. File references are
by function/section name rather than line number so they survive edits.

## What it computes

For each observed container, the `/dev` nodes it opened **beyond the runtime's
default device set** — i.e. the minimal explicit device grant:

```yaml
# my-app
# non-default device nodes the workload opened; the front-end maps these
# to compose devices: / docker --device (k8s requires a device plugin):
device_nodes:
  - /dev/fuse
```

Together with `advise_capabilities` this decomposes a lazy `privileged: true`
into its observed parts (`cap_add` + `devices:`) — with the honest caveat that
`privileged` also disables AppArmor/seccomp, which no open-tracing gadget can
observe.

## Pipeline at a glance

```
open(2) / openat(2) syscalls
  │
  └─ sys_exit_open{,at} tracepoint   open succeeded? → filter → resolve path
                                     from the returned fd → starts with
                                     "/dev/"? → count under (mntns, path)
  ▼
devices_per_mntns  (BPF hash: {mntns, path[512]} → count)
  │   GADGET_MAPITER → "devices" datasource, flushed ONCE at gadget stop
  ▼
WASM operator (go/program.go)   group rows by container
  ▼
advice package (go/advice)      subtract runtime default set → escaped YAML list
  ▼
"advise" datasource             one text packet per container
```

Two halves, deliberately split: the **eBPF half** records the smallest
sufficient signal (one map row per distinct opened `/dev` path per container);
the **WASM half** is a thin adapter around a pure, host-unit-testable `advice`
package that holds the only policy in the gadget — the default-device
exclusion list.

## The eBPF half (`program.bpf.c`)

### Exit-only: why there is no enter probe

Contrast with sibling `advise_filesystem`, which needs an enter/exit pair
(flags are an enter-side argument, the fd an exit-side result). Here the
open *flags don't matter* — any successful open of a device node implies the
container needs access to it — so every needed input is available at exit:
the returned fd (`ctx->ret`), the mntns id, and the path resolved *from* the
fd. Dropping the enter probe removes a whole map (`start`), one program, and
the pairing failure mode. This is the kind of simplification a reviewer should
expect to be deliberate, not accidental.

The `open(2)` variant is guarded by `#ifndef __TARGET_ARCH_arm64` because
arm64 never had the legacy `open` syscall — only `openat` exists there.
Syscall tracepoints (not kprobes) are used because they are a stable kernel
ABI, matching upstream `trace_open` which this program's path resolution is
adapted from.

### Exit walk (`trace_exit`)

```c
if (ret < 0) return 0;                        // ① failed open — no access granted
if (gadget_should_discard_data_current())     // ② container scoping (kernel-side)
        return 0;
k = bpf_map_lookup_elem(&keybuf, &z);         // ③ per-CPU scratch, not stack
__builtin_memset(k, 0, sizeof(*k));           //    zero — key equality depends on it
k->mntns_id_raw = gadget_get_current_mntns_id();
read_full_path_of_open_file_fd((int)ret, k->path, sizeof(k->path));  // ④
if (!is_dev_path(k->path)) return 0;          // ⑤ cheap prefix gate
v = bpf_map_lookup_or_try_init(&devices_per_mntns, k, &zero);
if (v) __sync_fetch_and_add(&v->count, 1);
else count_drop();                            // ⑥ loud, not silent
```

① Only *successful* opens count — a denied open granted nothing.

② `gadget_should_discard_data_current()` is IG's standard mntns filter:
`--containername foo` populates the `mntns_filter` map and everything outside
foo's mount namespace is dropped in the kernel, before any map traffic.

③ `struct dkey` is 8 + 512 = **520 bytes, larger than the 512-byte BPF
stack**, so it is built in a 1-entry `PERCPU_ARRAY`. Safe without locking:
the program runs to completion on one CPU without sleeping, so nothing can
interleave on the same CPU's slot. The `memset` is correctness, not hygiene —
the whole key is hashed, so identical `(mntns, path)` pairs must be
byte-identical.

④ `read_full_path_of_open_file_fd` (IG's `<gadget/filesystem.h>`, adapted
from Tracee) follows the just-returned fd to its `struct file` and walks the
dentry chain upward, crossing mount points, to the root of the opener's mount
namespace — yielding the canonical absolute path **as the container sees it**
(its own `/dev` is a runtime-populated tmpfs in its mntns). Symlinks and
`dirfd`-relative opens are already resolved by the kernel at open time.

⑤ `is_dev_path` is a 5-byte prefix compare (`/dev/`) done in BPF so
non-device opens — the overwhelming majority — never touch the map. It runs
on the *resolved* path, which has a nice property: opening a symlink that
points into `/dev` (e.g. `/tmp/link → /dev/fuse`) is still caught, because
resolution happened before the check. The pointer indexes constant offsets
into a fixed-size map-value buffer, so the verifier accepts it without a
bounds dance.

⑥ See [the drops contract](#the-drops-contract).

### Maps

| Map | Type | Size | Role | On overflow |
|---|---|---|---|---|
| `devices_per_mntns` | hash: `{mntns, path[512]}` → `{count}` | 4096 | the aggregate; one row per distinct opened /dev path per container | `count_drop()` — device lost, loudly |
| `keybuf` | 1-entry per-CPU array of `dkey` | 1 | 520-byte key scratch (stack limit) | n/a |
| `drops` | 1-entry array of u64 | 1 | failed-insert counter | n/a |

4096 *distinct* device paths across all observed containers is far beyond real
workloads (repeated opens only bump `count`); half `advise_filesystem`'s size
because `/dev` namespaces are small.

### The drops contract

An advisor must not silently under-report: a lost observation here is a device
missing from the grant, and enforcing the advice would break the workload.
Every failed insert increments `drops`; the WASM operator reads it at flush,
warns, and appends `# WARNING: N observation(s) dropped … recommendation may
be incomplete` to **every** advice packet (the counter is global —
attribution of a failed insert is ambiguous, so all output is marked).

## The datasource contract (`gadget.yaml`)

- `GADGET_MAPITER(devices, devices_per_mntns)` exposes the aggregate as the
  `devices` datasource.
- `ebpf.map.flush-on-stop: true` + `operator.oci.ebpf.map-fetch-interval: "0"`
  give advisor semantics: the map is iterated exactly once, at stop, so the
  WASM subscription sees the whole run in one batch.
- `cli.supported-output-modes: none` keeps raw rows off the CLI; `advise` is
  the CLI-facing datasource (output mode `advise`, raw text — the
  `advise_seccomp` convention).
- `mntns_id_raw` is typed `gadget_mntns_id`, enabling IG's per-row enrichment
  with `runtime.containerName` / `k8s.containerName`.

## The WASM half (`go/program.go`)

`gadgetInit` creates the `advise` output datasource (`DataSourceTypeSingle`,
one `text` field). `gadgetPreStart` resolves the `devices` datasource and its
field handles — any failure aborts the run; a schema mismatch between the BPF
program and the operator is a hard error, not a partial result — and
subscribes with `SubscribeArray(…, 9999)`: low priority (high number) so it
runs after IG's built-in operators, notably container-name enrichment.

The callback (fires once, with the whole flushed map):

1. Per row: `api.ShouldDiscardMntNsID` (belt-and-braces on top of the
   kernel-side filter), empty paths skipped.
2. Rows grouped by mntns id; the container name is captured from each group's
   first row (`k8s.containerName`, falling back to `runtime.containerName`
   for plain-Docker runs).
3. Packets emitted sorted by mntns id — deterministic multi-container output.
4. Each packet: `advice.Render(name, devices) + advice.OverflowWarning(dropped)`,
   with `dropped` read once per flush from the `drops` map via `api.GetMap`.

## The advice package (`go/advice`)

Pure Go, no `wasmapi` import — unit-testable on the host. This package holds
the one piece of policy in the gadget:

- `defaultDevices` / `defaultPrefixes` — the nodes a runtime provides in every
  container (Docker's default set: `null`, `zero`, `full`, `random`,
  `urandom`, `tty`, `console`, `ptmx`, plus the `fd`/`stdin`/`stdout`/`stderr`
  symlinks) and the default subtrees (`/dev/pts/`, `/dev/shm/`,
  `/dev/mqueue/` — allocated terminals, POSIX shm and message queues). Opening
  these never needs a `devices:` grant, so recommending them would be pure
  noise; they are subtracted, not reported.
- `NonDefaultDevices` — filter to non-default `/dev` paths, deduplicate, sort.
  The `/dev/` prefix re-check is defensive (the eBPF side already gates on it).
- `Render` — with no non-default opens it emits an explicit "no device grant
  required" comment, never an empty `device_nodes:` key; entries sorted for
  diffable output. The output is deliberately **neutral paths, not
  major:minor pairs or cgroup rules** — Compose `devices:` and `docker
  --device` take paths, host↔container remapping is a front-end concern, and
  k8s has no direct securityContext equivalent (device plugins own that), so
  the gadget emits the one representation every consumer can map from.
- **Every path goes through `yamlScalar`** (`yaml.go`) — same security
  boundary as `advise_filesystem`: a device-node name is workload-visible
  data (any byte except NUL and `/` is legal in a path component), and the
  advice is YAML that downstream tooling parses and applies to privilege. A
  container that could get a node like `/dev/x\nprivileged: true` rendered
  bare would inject a top-level YAML key into its own recommendation.
  `yamlScalar` emits conservative path-like strings unquoted and
  double-quotes-and-escapes everything else, so no byte can escape the scalar.
  `commentText` strips control characters from the container name rendered in
  the leading `# comment` (comments can't be escaped, only broken by a line
  break).
- `OverflowWarning` — the drops count as a YAML *comment*, keeping the output
  machine-parseable even when incomplete.

## What the tests pin down

Unit (`go/advice/advice_test.go`): the default-set subtraction (defaults and
default-prefix subtrees excluded, non-defaults kept), dedup/sorting, the
no-grant rendering, and the YAML-injection case (a newline-bearing device path
renders as one quoted scalar, plus the converse guard that ordinary paths stay
unquoted). The comment sanitizer is the same logic as the siblings'; its
injection test lives in their `advice` packages.

E2E (`test/e2e.sh`): builds the image, runs a container that opens `/dev/fuse`
(a canonical non-default node) while also touching default nodes, and asserts
the advice grants `/dev/fuse` and does **not** list defaults like `/dev/null`
— the live proof of the pipeline including the subtraction.

## Accuracy analysis — where it can be wrong

Over-approximation:

- Open-*attempt* granularity: a device opened once during startup probing
  (e.g. a library enumerating `/dev`) is recommended even if never used
  again. Conservative in the safe direction; the `count` field in the raw
  datasource lets a front-end rank.

Under-approximation (the dangerous direction, hence the loud overflow design):

- **Observation window** — only devices touched during the run are seen; a
  signal, not a proof.
- **Map overflow** — counted and stamped into the output (`drops`).
- **Non-open access paths**: ioctl/read/write on an fd *inherited* from
  outside the observation window, device nodes `mknod`-ed outside `/dev`
  (needs `CAP_MKNOD`, which `advise_capabilities` would surface), or a device
  bind-mounted to a non-`/dev` path in the container — all invisible to a
  `/dev/`-prefixed open trace. Also `openat2(2)` and io_uring's
  `IORING_OP_OPENAT` bypass these tracepoints entirely.
- **The default set is Docker's.** A runtime with a different default set
  needs the exclusion list adjusted (it is one table in `go/advice`); a wrong
  default set errs toward *listing* a device the runtime already provides —
  noisy, not breaking.

## Hard questions a reviewer might ask

**Q: Why trace opens instead of hooking the cgroup device controller
(`cgroup/dev` BPF program), which is the actual enforcement point?**
A `cgroup/dev` program sees checks by major:minor with no path, must be
attached per-cgroup, and on cgroup v2 would sit alongside the runtime's own
device program. Open-tracing reuses the existing, audited `trace_open` path
resolution, needs zero per-container setup, and emits paths — the
representation Compose/docker take. The trade-off (missing non-open access) is
documented above.

**Q: Why emit paths rather than major:minor device numbers?**
Every consumer format in scope (`devices:` in Compose, `--device` in Docker)
takes paths; major:minor would force each front-end to map back. The kernel
`struct file` *does* carry the rdev if a future consumer needs it — an easy
additive change to the map value.

**Q: The container's `/dev/foo` might be a different device than the host's
`/dev/foo` — whose view is reported?**
The container's: the path is resolved inside the opener's mount namespace.
That is the correct frame for the advice ("this workload opens `/dev/fuse` in
its namespace"); how a front-end maps that to a host device in the grant is
that front-end's remapping concern, stated in the Render doc comment.

**Q: `/dev/stdin` is in the default list, but resolution follows symlinks —
does that entry ever match?**
Rarely, and that is fine: opening `/dev/stdin` resolves to the *target* file
(the fd's real path), which is then usually not a `/dev` path at all and is
dropped by `is_dev_path`. The symlink entries in the default set are
defensive, for the corner where the target itself is a default `/dev` node.

**Q: Why is the default-set subtraction in the advice package instead of the
BPF program?**
It is policy, and policy belongs where it is cheap to test, change, and review
— a Go table with unit tests, not a BPF string-compare chain that would grow
per entry and re-verify per kernel. The BPF side does only the cheap,
policy-free `/dev/` gate to keep map traffic near zero.

**Q: Doesn't this plus `advise_capabilities` fully replace `privileged:
true`?**
No, and the README says so explicitly: `privileged` also disables
AppArmor/seccomp confinement and mounts `/dev` unrestricted. The pair
decomposes the *capability and device* dimensions of privileged; the LSM
dimension is `advise_seccomp`'s territory (and AppArmor advice is out of
scope for open-tracing entirely).

**Q: What does a run with zero device opens produce?**
If no rows survive filtering, no group exists and no packet is emitted for
that container — the front-end treats "no output" as "no grant observed". A
container that opened only *default* nodes does produce a packet: the
explicit "no device grant required" comment, which is a stronger, positive
statement.
