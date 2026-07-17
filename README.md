# ig-advise-gadgets

Three [Inspektor Gadget](https://inspektor-gadget.io) (IG) image-based
**advisor** gadgets that derive least-privilege container settings from live
observation. Each is a self-contained, signable OCI image built with
`ig image build`: the eBPF signal + per-container mechanical aggregation live in
the gadget, while opinionated judgement (observation-window policy, confidence
grading, output formatting for Compose/k8s/OCI) is deliberately left to
downstream tooling.

| Gadget | Emits | Validated |
|---|---|---|
| [`advise_capabilities`](advise_capabilities) | k8s `securityContext` capabilities (`drop: [ALL]` + minimal `add:`); runtime-setup caps excluded | unit + e2e (CAP_CHOWN container → `add: [CHOWN]`, no setup caps) |
| [`advise_filesystem`](advise_filesystem) | `readOnlyRootFilesystem: true` + the `writable_paths:` the workload needs | unit + e2e (file-writer → `/var/lib/app` writable) |
| [`advise_devices`](advise_devices) | minimal `device_nodes:` list (runtime default set excluded) | unit + e2e (`/dev/fuse` opener → grant, defaults excluded) |

## Why these three

Determined against IG v0.51.0 (issue/PR search + gadget catalog): IG ships only
two advisor gadgets — `advise_networkpolicy` and `advise_seccomp` — plus raw
tracers (`trace_open`, `trace_capabilities`, …). There is no advisor for
capabilities (upstream issue
[#173](https://github.com/inspektor-gadget/inspektor-gadget/issues/173), a
maintainer-endorsed request open since 2021), none for read-only rootfs + tmpfs,
and none for `/dev` grants. These gadgets fill those gaps, built to the
`advise_seccomp` conventions so any of them can be proposed upstream.

`advise_capabilities` is built to the upstream `advise` bar (see issue #173): it
excludes runtime-setup noise via ig's own container-registration boundary (not a
comm-based hack — see the design note below), emits a k8s `securityContext`
(the stated target on #173), and keeps opinionated judgement OUT of the gadget.
The other two gadgets follow the same division.

All three: eBPF (amd64+arm64) + Go→WASM operator compile via `ig image build`;
pure aggregation host-unit-tested under `go/advice`; live signal verified by
`test/e2e.sh`. CI in `.github/workflows/gadgets.yml` matrixes over them.

## Conventions

Each gadget mirrors IG's `advise_seccomp`: a `program.bpf.c` that aggregates per
mount namespace via `GADGET_MAPITER`, a `gadget.yaml` with a raw datasource
(`cli.supported-output-modes: none`, `ebpf.map.flush-on-stop: true`) plus an
`advise` datasource, and a WASM operator (`go/program.go`) that renders the
recommendation.

**Upstreaming:** to propose any of these to IG core, swap `go/go.mod` to the
in-tree `module main` + `replace` form (in-tree `advise_seccomp` keeps its
aggregation in a WASM operator, so the WASM shape can carry over; a core
`generate_*` operator per `advise_networkpolicy` is the alternative). Start with
`advise_capabilities` against the endorsed, unbuilt issue #173 — comment there to
confirm current maintainer appetite before opening a PR.

## Differences from core Inspektor Gadget

These gadgets are **advisors**, not tracers, and they differ from the core
capabilities/open tooling in specific, intentional ways a reviewer should know:

**`advise_capabilities` vs the core `trace_capabilities` tracer**

| | `trace_capabilities` (core) | `advise_capabilities` (here) |
|---|---|---|
| Output | one event per capability check (stream) | one k8s `securityContext` per container (aggregate) |
| Aggregation | none | per-mntns union of held caps (u64 bitmap over the 41 caps), flushed on stop |
| Denials | reports `capable=false` too | **held-only** — a denied check means the cap isn't in the workload's granted set; insufficiency is a downstream verification concern |
| Runtime setup noise | reported (raw tracer) | excluded via ig's container-registration boundary; no comm-based filter (see design note) |
| Rich context | audit flag, insetid, kernel/user stack, syscall, userns | **dropped** — an advisor needs "which caps, per container," not forensics |
| Kept from core | — | the real-vs-subjective credential guard (overlayfs copy-up) so overridden-cred checks don't inflate the set |

So `advise_capabilities` is `trace_capabilities`'s signal, reduced to the
minimal per-container grant and rendered as the artifact issue #173 asks for. It
is **not** a replacement for the tracer — it answers a different question.

**`advise_filesystem` / `advise_devices` vs core**

IG has **no** open-based advisor; core ships only the `trace_open` tracer. These
add per-container aggregation of write-intent opens (→ `readOnlyRootFilesystem` +
writable dirs) and `/dev` opens (→ non-default device nodes), both
runtime-suppressed and mntns-keyed, reusing `trace_open`'s path resolution.

**Shared, honest limits (all three)**

- Dynamic-observation floor: only what the workload exercised in the window is
  seen — a signal, not a proof; grade confidence before enforcing.
- The capability bit→name mapping assumes kernel order (0..40); guarded by a unit
  test against the canonical list.
- Opinionated judgement — confidence grading, entrypoint cross-checks,
  volume-vs-tmpfs correlation, Compose/OCI formatting — is deliberately **not**
  in these gadgets; it belongs in downstream tooling. That scoping is what keeps
  them upstream-acceptable.

### Design note: runtime-setup ("runc") noise

These gadgets do **not** special-case the container runtime by process name
(`comm == runc[:...]`). An earlier revision did, matching `advise_seccomp`'s
runc-awareness, but it was removed because:

- It is a **no-op on the container-scoped path**. Under `--containername`, ig's
  container-registration boundary already excludes the runtime's setup activity
  (it runs before the container's mount namespace is tracked). A verified
  with/without-suppression differential produced identical output there.
- Comm-string matching is **fragile and runtime-specific**: it catches `runc`
  but not `crun`, `youki`, or other OCI runtimes IG users run under
  containerd/CRI-O/Podman.

So setup-noise exclusion relies on ig's own container boundary, which is
runtime-agnostic. Explicit setup-noise filtering for the **whole-host**
observation path (where the runtime's setup *is* visible) is deferred to the
upstream design discussion on issue #173, so it can be solved consistently with
how IG already handles this for `advise_seccomp` rather than with a bespoke
heuristic here.

## Build / run

```sh
sudo ig image build advise_capabilities -t advise_capabilities:dev
sudo ig run advise_capabilities:dev --containername my-app --timeout 30
```

The pinned IG version lives in [`IG_VERSION`](IG_VERSION); keep each gadget's
`go/go.mod` IG require in lockstep with it.

## Licensing

- eBPF (`program.bpf.c`): **GPL-2.0** ([`LICENSE-bpf.txt`](LICENSE-bpf.txt)) —
  required, they use GPL-restricted BPF helpers, and they adapt code from IG's
  `trace_capabilities` / `trace_open` / `advise_seccomp` (attribution retained
  in each file header).
- Everything else (WASM operators, `advice` packages, scripts): **Apache-2.0**
  ([`LICENSE`](LICENSE)), matching IG's Go code.
