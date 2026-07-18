# advise_capabilities — internals

A function-by-function walkthrough of how the gadget works. The
[`README.md`](README.md) covers *what* it is and how to run it; this document
covers *how* it works and *why* each piece is the way it is. File references are
by function/section name rather than line number so they survive edits.

## What it computes

For each observed container, the union of Linux capabilities the workload
**held when the kernel checked them** — i.e. the minimum `cap_add` set — and a
rendered Kubernetes `securityContext` capabilities block:

```yaml
# my-postgres
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - CHOWN
      - SYS_NICE
```

## Pipeline at a glance

```
kernel: cap_capable(cred, ns, cap, opts)          [every capability decision]
  │
  ├─ kprobe  ig_cap_e   filter → real-cred guard → stash cap# in `start`
  └─ kretprobe ig_cap_x ret==0 (held)? → OR bit `cap` into per-container bitmap
  ▼
caps_per_mntns  (BPF hash: mntns id → u64 bitmap)
  │   GADGET_MAPITER → "capabilities" datasource, flushed ONCE at gadget stop
  ▼
WASM operator (go/program.go)   one row per container: read bitmap + names
  ▼
advice package (go/advice)      bitmap → sorted cap names → YAML block
  ▼
"advise" datasource             one text packet per container
```

Two halves, deliberately split: the **eBPF half** produces the smallest
sufficient signal (one u64 per container); the **WASM half** is a thin adapter
around a pure, host-unit-testable `advice` package. Opinionated judgement
(observation-window policy, confidence, output formats beyond k8s) is
intentionally not here — see the scoping note in the top-level
[`README.md`](../README.md).

## The eBPF half (`program.bpf.c`)

### Why hook `cap_capable`

`cap_capable()` (security/commoncap.c) is the capability-LSM implementation
behind `security_capable()`, which is what `capable()`, `ns_capable()`,
`file_ns_capable()` and friends all call. Hooking it observes **every
capability decision in the kernel**, regardless of which syscall or subsystem
triggered it — one hook instead of hundreds of syscall-specific ones.

Alternatives, and why not:

- **A tracepoint** — there is no stable tracepoint for capability checks.
- **BPF-LSM (`lsm/capable`)** — needs `CONFIG_BPF_LSM=y` *and* `bpf` in the
  `lsm=` boot parameter; a kprobe works on any BTF-enabled kernel. The kprobe
  approach also matches upstream IG's `trace_capabilities`, which this program
  is derived from — staying close to upstream is a deliberate reviewability
  property.

### Why a kprobe/kretprobe *pair*

The two facts we need live at different times: the **capability number** is an
argument (entry only) and the **verdict** is the return value (exit only). The
`start` hash map bridges them, keyed by `bpf_get_current_pid_tgid()` (unique
per thread), the same pattern upstream `trace_capabilities` uses:

1. `ig_cap_e` (entry) stashes `{cap}` under the thread's id.
2. `ig_cap_x` (exit) looks the stash up, deletes it, and acts on the verdict.

`cap_capable` does not sleep or recurse in practice, so at most one stash per
thread is in flight; `BPF_ANY` on insert makes an overwrite harmless anyway.

### Entry probe walk (`ig_cap_e`)

```c
if (gadget_should_discard_data_current())  // ① container scoping
        return 0;
task = bpf_get_current_task();
real_cred = BPF_CORE_READ(task, real_cred);
if (cred != real_cred)                     // ② subjective-credential guard
        return 0;
if (cap_opt & CAP_OPT_NOAUDIT)             // ③ non-audit (opportunistic) guard
        return 0;                          //   (int-audit form on kernels <5.1)
args.cap = cap;
if (bpf_map_update_elem(&start, &pid_tgid, &args, BPF_ANY))
        count_drop();                      // ④ loud, not silent
```

① `gadget_should_discard_data_current()` is IG's standard mntns-based filter:
`ig run --containername foo` populates the `mntns_filter` map with foo's mount
namespace id, and this call drops events from every other namespace *in the
kernel*, before any map traffic. `#include <gadget/mntns_filter.h>` is forced
so the filter map exists even though this file never touches it directly.

② The guard compares the credentials the check is being made with (`cred`
argument) against the task's `real_cred`. They differ when the kernel is
running with **overridden (subjective) credentials** via `override_creds()` —
the canonical case is overlayfs copy-up, which acts with the mounter's creds.
Recording those checks would attribute the *mounter's* capabilities to the
container and inflate the recommendation. This guard is inherited verbatim
from upstream `trace_capabilities`.

③ **Non-audit checks are excluded.** The kernel marks opportunistic
capability probes with `CAP_OPT_NOAUDIT` — "does this task happen to have the
cap?" checks whose denial is normal operation, the canonical one being the
`CAP_SYS_ADMIN` probe in every `execve`'s memory-overcommit accounting.
Such a check *succeeds* whenever the capability is merely held, so without
this guard the advisor's headline use case — observing an over-privileged
container to derive its minimal set — breaks: any exec'ing container granted
`SYS_ADMIN` would get `SYS_ADMIN` recommended back (verified live before the
guard was added). bcc's `capable` and IG's `trace_capabilities` hide these
checks by default (the exact concern a maintainer raised on upstream issue
#173); the advisor makes the filter unconditional rather than a param — an
advisor has no forensic use for non-audit checks. Kernels < 5.1 pass an
`int audit` (1 = audited) instead of `CAP_OPT_*` flags, handled via a
`LINUX_KERNEL_VERSION` guard exactly as upstream does.

④ See [The drops contract](#the-drops-contract).

### Exit probe walk (`ig_cap_x`)

```c
ap = bpf_map_lookup_elem(&start, &pid_tgid);   // pair with entry; miss → ignore
bpf_map_delete_elem(&start, &pid_tgid);        // always clean up
if (PT_REGS_RC(ctx) != 0) return 0;            // ① held-only
if (cap < 0 || cap >= CAP_MAX) return 0;       // ② bitmap bounds (CAP_MAX=64)
key.mntns_id_raw = gadget_get_current_mntns_id();
bitmap = bpf_map_lookup_or_try_init(&caps_per_mntns, &key, &blank_val);
__sync_fetch_and_or(&bitmap->caps, 1ULL << cap);  // ③ atomic union
```

① **Held-only**: `cap_capable` returns 0 iff the task's effective set contains
the capability (in the target user namespace). A non-zero return is a denial —
the workload does *not* have that capability, so it cannot belong to the
minimum granted set. Denials are a *verification* signal ("the current grant
is insufficient"), which is downstream tooling's job, not the advisor's.

② `CAP_MAX` is 64 (the bitmap width), not 41 (the current highest capability +
1). A future kernel capability 41–63 is safely *recorded*; rendering it needs a
`CapNames` update (see [accuracy analysis](#accuracy-analysis--where-it-can-be-wrong)).

③ `__sync_fetch_and_or` makes concurrent updates from multiple CPUs safe; a
bitmap union is naturally idempotent and order-independent, which is why a u64
bitmap is the ideal aggregate here — no per-event output, no ordering concerns,
constant memory per container.

### Maps

| Map | Type | Size | Role | On overflow |
|---|---|---|---|---|
| `caps_per_mntns` | hash: `{mntns}` → `{u64 caps}` | 1024 | the aggregate; one row per container | `count_drop()` — container's caps lost, loudly |
| `start` | hash: `pid_tgid` → `{cap}` | 10240 | entry→exit argument stash | `count_drop()` — one check missed, loudly |
| `drops` | 1-entry array of u64 | 1 | failed-insert counter | n/a |

1024 containers and 10240 concurrent in-flight capability checks are far above
realistic single-node numbers; the sizes are fixed because BPF maps must be,
and the `drops` counter exists precisely so hitting a limit is never silent.

### The drops contract

An advisor's worst failure mode is **silent under-reporting**: a dropped
observation means the recommendation is missing a capability the workload
needs, and enforcing it would break the workload. Every failed map insert
increments `drops`; the WASM operator reads it at flush and (a) logs a warning
and (b) appends `# WARNING: N observation(s) dropped … recommendation may be
incomplete` to **every** advice packet. The counter is global (not
per-container) by design — attribution of a failed insert is ambiguous, so the
warning is conservatively stamped on all output.

## The datasource contract (`gadget.yaml`)

- `GADGET_MAPITER(capabilities, caps_per_mntns)` exposes the aggregate map as
  an iterable datasource named `capabilities`.
- `ebpf.map.flush-on-stop: true` + `paramDefaults:
  operator.oci.ebpf.map-fetch-interval: "0"` give **advisor semantics**: no
  periodic fetch; the map is iterated exactly once, when the gadget stops. That
  is why the WASM subscription fires once with the complete run's data.
- `cli.supported-output-modes: none` on `capabilities` keeps the raw bitmap
  rows out of the CLI (they are consumed by the WASM operator, though other
  programmatic consumers can still read them); the `advise` datasource is
  CLI-facing with output mode `advise` (raw text, the same mode
  `advise_seccomp` uses).
- The map key field `mntns_id_raw` is typed `gadget_mntns_id`, which is what
  lets IG's enrichment attach `runtime.containerName` / `k8s.containerName` to
  each row and lets the WASM side map ids to tracked containers.

## The WASM half (`go/program.go`)

Lifecycle: `gadgetInit` creates the output `advise` datasource
(`DataSourceTypeSingle`, one `text` field); `gadgetPreStart` resolves the
input datasource + field handles and subscribes. Failing any resolution
returns non-zero, which aborts the gadget run — a schema mismatch between
`program.bpf.c` and the operator is a hard error, not a partial result.

`SubscribeArray(…, 9999)` registers at low priority (high number) so it runs
**after** IG's built-in operators have processed the batch — in particular
after container-name enrichment. Because of flush-on-stop, the callback runs
once, with the whole map as a `DataArray`. Per row:

1. Read `mntns_id_raw`; `api.ShouldDiscardMntNsID(id)` drops rows that do not
   belong to a currently-tracked, selected container — belt-and-braces on top
   of the kernel-side filter, same as `advise_seccomp`.
2. Read the `caps` bitmap.
3. Container name: prefer `k8s.containerName`, fall back to
   `runtime.containerName` (plain-Docker runs have no k8s name).
4. Emit one single-packet datasource entry:
   `advice.Render(name, bitmap) + advice.OverflowWarning(dropped)`.

`droppedObservations()` reads the `drops` map by direct map access
(`api.GetMap` / `Lookup`) — the counter is not a datasource, just a value the
operator polls once at flush.

## The advice package (`go/advice`)

Pure Go, no `wasmapi` import — so it unit-tests on the host with plain
`go test` (the WASM build only compiles the thin adapter around it).

- `CapNames` — index = kernel capability number, value = name without `CAP_`
  prefix (the k8s/compose convention). **This ordering is the single most
  correctness-critical data in the gadget**: a transposed entry would
  recommend the *wrong capability*. It is pinned by a unit test against an
  independently-written canonical list (see below).
- `HeldCaps` — decode bitmap → sorted, deduplicated names; bits ≥ 41 ignored.
- `Render` — invariants: always `drop: [ALL]` (deny-by-default is the point of
  the advisor); `add:` only when non-empty (an empty bitmap renders an explicit
  "no add required" comment, never a dangling `add:` key); entries sorted for
  deterministic, diffable output.
- `commentText` (in `yaml.go`) — the container name is workload-adjacent data
  rendered into a `# comment`; comments cannot be escaped, only broken out of
  by a line break, so all control characters are replaced with spaces. Without
  this, a container named `app\nprivileged: true` would inject a top-level YAML
  key into the advice. (Capability *names* come from the static `CapNames`
  table, so the list body needs no escaping — unlike the path-emitting sibling
  gadgets.)
- `OverflowWarning` — renders the drops count as a YAML **comment**, so the
  advice stays machine-parseable even when incomplete.

## What the tests pin down

Unit (`go/advice/advice_test.go`):

- `TestCapNamesMatchKernelOrder` — `CapNames` matches an independent canonical
  list, and is exactly 41 entries (catches silent truncation/extension).
- `TestHeldCapsDecode` — decode of edge bits (0, 21, 40, >40 ignored), sorting.
- `TestRenderAlwaysDropsAll` / `TestRenderEmptyHasNoBareAdd` — the two Render
  invariants above.
- `TestRenderCommentInjectionSanitized` — the newline-in-container-name attack.
- `TestOverflowWarning` — warning stays a comment and carries the count.

E2E (`test/e2e.sh`): builds the image, runs a busybox container `chown`-ing in
a loop **with `--cap-add SYS_ADMIN` deliberately granted**, observes 8s, and
asserts the output is a `securityContext` block with `drop: ALL`, `add: CHOWN`,
and — the minimality check — **no** `SYS_ADMIN`/`MKNOD`. The SYS_ADMIN grant
makes that assertion do double duty: every `execve` in the loop triggers a
non-audit `CAP_SYS_ADMIN` overcommit check this container passes, so the
assertion is a live regression test for the non-audit filter (and, as before,
for runtime-setup noise being excluded by ig's container-registration boundary
without any comm filter). The gadgetrunner unit test mirrors this: its runner
is full-caps host root, execs a child, and `SYS_ADMIN` is asserted absent.

## Accuracy analysis — where it can be wrong

Over-approximation (recommends more than strictly needed):

- **Nested user namespaces.** `cap_capable` is called per user namespace; a
  workload that creates its *own* userns (`unshare -U`, rootless
  container-in-container) holds full capabilities inside it, and audited
  checks against that child namespace succeed without any grant on the real
  container — yet they are recorded like any other held check. Enforcing the
  advice still works (the nested userns keeps granting itself caps), so this
  errs safe but can list caps the container doesn't need granted. Upstream
  `trace_capabilities` exposes current/target userns ids for exactly this
  analysis; filtering checks whose target userns is workload-owned is
  possible future work. (The formerly-listed opportunistic-check
  over-approximation is now closed by the non-audit guard in the entry
  probe.)

Under-approximation (misses things the workload needs — the dangerous
direction, hence the loud-overflow design):

- **Observation window.** Only what ran during the window is seen. This is the
  inherent floor of dynamic observation; the advice is a signal to grade, not
  a proof (stated in every README).
- **Map overflow.** Counted and stamped into the output (`drops`).
- **Kretprobe misses.** Under extreme load the kernel can miss kretprobe
  returns (maxactive exhaustion); these are not counted by `drops`. Rare, and
  shared with upstream `trace_capabilities`.
- **Future capabilities.** A kernel cap ≥ 41 is recorded in the bitmap but not
  rendered until `CapNames` grows; the 41-entry unit-test assertion is the
  tripwire forcing that update to be conscious.

## Hard questions a reviewer might ask

**Q: Why not just parse `/proc/<pid>/status` CapEff, or use the container
runtime's config?**
Those show what a container *is granted*, not what it *uses*. The entire point
is to derive the minimum from observed use, so over-broad grants can be cut.

**Q: A denial (`ret != 0`) means the workload *wanted* a capability it lacks —
why throw that away?**
Because it doesn't belong in the *minimum grant derived from observation*: the
workload ran without it. "The current grant is insufficient" is a verification
finding about a *candidate policy*, a different artifact with different
consumers; mixing it into the advice would make the output non-mechanical.
Downstream tooling can run the candidate policy and watch for new denials.

**Q: The workload runs as root with all caps — doesn't every check succeed,
inflating the set?**
Only checks that *happen* are recorded, and the two classes of check that
happen without reflecting need are both filtered: subjective-credential
checks (guard ②) and non-audit opportunistic checks (guard ③ — without which
any full-caps container that ever exec'd would be recommended `SYS_ADMIN`,
verified live). Running as root doesn't make the kernel *audit-check*
capabilities the workload never functionally triggers; the residual inflation
is the nested-userns case in the accuracy analysis.

**Q: Why key by mount namespace and not cgroup id / pid?**
Mntns id is IG's canonical container identity: the whole gadget framework
(filtering, enrichment, `--containername`) is built on it, and following
`advise_seccomp`'s conventions is an explicit upstreamability goal. Pids churn;
one container = one mntns for the workloads this targets.

**Q: What about two containers sharing a mount namespace?**
They aggregate as one entry — same behavior as `advise_seccomp` and IG's
mntns-based tooling generally; an accepted framework-level limitation.

**Q: Why is there no `runc`/`comm` filter like `advise_seccomp` has?**
Measured to be a no-op under `--containername` (ig registers the container's
mntns only after runtime setup, so setup activity never passes the filter —
the e2e's no-`SYS_ADMIN` assertion proves it live), and comm-matching is
fragile (misses `crun`, `youki`, …). Whole-host-mode setup filtering is
deferred to the upstream design discussion (issue #173). Full rationale: the
design note in the top-level [`README.md`](../README.md).

**Q: In-tree `advise_seccomp` deliberately does NOT filter kernel-side — its
image-based port (IG PR #4089) found that dropped runc's bootstrap syscalls.
Why is kernel-side filtering right here?**
Because the polarity is inverted. A seccomp profile is installed before exec
and applies to the runtime's bootstrap, so bootstrap syscalls must be *in*
the profile or the container cannot start — kernel-side filtering breaks the
artifact. A capability grant applies only to the container's own processes;
the runtime does its setup with its own full privileges, so setup caps must
be *out* of the grant to keep it minimal. Same registration-boundary
mechanism, opposite requirement — see the design note in the top-level
README.

**Q: Why does aggregation live in the WASM operator instead of a core IG
`generate_*` operator?**
Out-of-tree, WASM is the only extension surface — and in-tree `advise_seccomp`
*also* keeps aggregation in WASM, so the shape can carry upstream as-is. A
core operator (as `advise_networkpolicy` uses) is the alternative to raise
with maintainers on issue #173.

**Q: Is the YAML safe to machine-apply?**
The only dynamic values are the container name (comment-sanitized, control
chars stripped) and the drops count (an integer). Capability names come from a
static table. The `drop: [ALL]` line is unconditional. So no workload-
controlled bytes can reach a YAML *node* — see `yaml.go` and the injection
unit test; the path-emitting sibling gadgets carry the full scalar-escaping
story.

**Q: What load does this add?**
Two short BPF programs on a hot-ish path (`cap_capable`), one hash update per
check pair, no per-event userspace traffic at all — the only data transfer is
one map iteration at stop. This is the cheapest of the three gadgets.
