# advise_capabilities gadget

An Inspektor Gadget [image-based gadget](https://inspektor-gadget.io/docs/latest/gadget-devel/)
that derives the **minimum Linux capability set each container actually uses**,
by tracing `cap_capable()` and unioning the held capabilities per container.

The gadget owns the capability *signal + mechanical aggregation* as a
self-contained, signable OCI image. Opinionated derivation — init-window
suppression, confidence grading, entrypoint cross-checks, and Compose/k8s/OCI
formatting — deliberately stays in downstream tooling, not in the gadget.

For a function-by-function walkthrough of how the gadget works (eBPF hooks,
maps, WASM operator, accuracy analysis), see [`internals.md`](internals.md).

## What it emits

Two datasources:

- `capabilities` — the raw per-container held-capability bitmap (a
  `GADGET_MAPITER` over an mntns-keyed eBPF map, flushed on stop). Not rendered
  directly; consumed by the WASM operator and available to consumers.
- `advise` — the WASM operator's output: a Kubernetes `securityContext`
  capabilities block (`drop: [ALL]` + the minimal `add:`) per container — the
  artifact upstream issue #173 asks for. This is the *mechanical* union;
  downstream tooling can reshape it into Compose/docker-run/OCI forms and apply
  its own coverage/confidence judgement before anything is enforced.

### Runtime-setup ("runc") noise

The derived set excludes the container runtime's setup caps via ig's own
container-registration boundary — under `--containername`, the runtime's setup
runs before the container's mount namespace is tracked, so those caps never reach
the gadget. This gadget deliberately does **not** special-case the runtime by
process name (a `comm == runc` filter would be a no-op here and would miss
`crun`/`youki`); explicit whole-host setup filtering is deferred to issue #173.
See the design note in [`../README.md`](../README.md#design-note-runtime-setup-runc-noise).

## Build / sign / push

```sh
# Build (compiles the eBPF for amd64+arm64 and the Go WASM operator):
sudo ig image build advise_capabilities -t ghcr.io/<you>/advise_capabilities:0.1.0

# Sign with your cosign key:
sudo ig image sign ghcr.io/<you>/advise_capabilities:0.1.0

# Push:
sudo ig image push ghcr.io/<you>/advise_capabilities:0.1.0

# Run against a live container (needs root: CAP_BPF/CAP_PERFMON):
sudo ig run ghcr.io/<you>/advise_capabilities:0.1.0 --containername my-app
```

> `ig image build` compiles without root; `ig image push` writes the local OCI
> store under `/var/lib/ig` and `ig run` loads eBPF — both need root (or a
> one-time `sudo install -d -o "$USER" /var/lib/ig`). See `dev.md`.

## Relationship to Inspektor Gadget core

IG already ships `advise networkpolicy` and `advise seccomp`, but **not** a
capability advisor. The gap is a long-standing, maintainer-endorsed feature
request — upstream issue **#173 "New Gadget: Capability Advisor"** (open since
2021; a lead maintainer listed *"generate the PodSecurityContext with the right
capabilities"* as the remaining task). This gadget is built to the upstream
advise-family conventions (`advise_seccomp` is the closest template) so it can be
proposed upstream with minimal rework:

- **This repo:** aggregation lives in the bundled WASM operator
  (`go/program.go`) — self-service, no core changes. In-tree `advise_seccomp`
  uses the same WASM shape, so this may carry over as-is.
- **Alternative upstream shape:** the aggregation could instead move to a core
  `generate_capabilitypolicy`-style operator enabled by a datasource annotation,
  as `advise networkpolicy` uses `generate_networkpolicy.enable` — a question
  for the maintainers on #173.

Before opening an upstream PR, revive issue #173 to confirm current maintainer
appetite (it is `priority/P4` and went stale).

## Attribution / licensing

- `program.bpf.c` adapts the `cap_capable` hooking from IG's `trace_capabilities`
  gadget (GPL-2.0) and the per-mntns `GADGET_MAPITER` pattern from `advise_seccomp`.
  It is **GPL-2.0** (required — it uses GPL-restricted BPF helpers).
- `go/program.go` (the WASM operator) is **Apache-2.0**, matching IG's Go code, to
  ease a future upstream contribution.

## Limitations

- Records only *held* capabilities (`cap_capable` returned 0). Denials are not
  emitted — insufficient/over-permissioned classification is left to downstream
  verification.
- Dynamic-observation floor: only what the workload exercises in the window is
  seen. This is a *signal*, not a correctness proof — grade confidence and check
  coverage before enforcing the result.
- If an eBPF map fills during the run, dropped observations are counted and a
  `# WARNING` comment is appended to the advice (plus an operator warning) —
  treat such a result as incomplete.
