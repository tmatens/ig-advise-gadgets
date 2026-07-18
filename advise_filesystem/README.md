# advise_filesystem gadget

An Inspektor Gadget image-based gadget that derives a **read-only root filesystem
+ the `tmpfs:` paths a container actually mutates**, by tracing write-intent
`open`/`openat` calls plus metadata-only mutations (`mkdir`, `unlink`, `rename`,
`truncate`, `chmod`, … via the `security_path_*` LSM hooks) and unioning the
affected directories per container.

Like `advise_capabilities`, the write-path signal + mechanical aggregation live
on IG's extension surface as a self-contained, signable OCI image. The
opinionated half — correlating writes against mounted volumes (a written path on
a volume should stay a volume, not become tmpfs), confidence grading, and
multi-format output — belongs in downstream tooling.

For a function-by-function walkthrough of how the gadget works (eBPF hooks,
maps, WASM operator, accuracy analysis), see [`internals.md`](internals.md).

## What it emits

- `files` — raw per-(container, path) map iterator of observed mutations (mntns
  key + resolved `path` + `count` file-write events + `dir_writes`
  directory-entry mutations), flushed on stop. Consumed by the WASM operator.
- `advise` — the k8s `securityContext` field `readOnlyRootFilesystem: true` plus a
  neutral `writable_paths:` list of the directories the container wrote to, one
  packet per container. Downstream tooling maps `writable_paths` to Compose
  `tmpfs:`, k8s `emptyDir` volumes, or a persistent volume where a path must
  survive.

Runtime-setup writes are excluded via ig's container-registration boundary (no
comm-based runtime filter); see the design note in
[`../README.md`](../README.md#design-note-runtime-setup-runc-noise).

## Prior art

IG ships **no** read-only-filesystem/tmpfs advisor and none was ever proposed
(searched issues/PRs: "read-only", "readonly rootfs", "tmpfs advise", "immutable
filesystem" — zero results). It ships the `trace_open` *tracer* this gadget's
eBPF is adapted from. This is greenfield; built to the `advise_seccomp`
conventions for a possible upstream contribution alongside
`advise_capabilities`.

## Build / run

```sh
sudo ig image build advise_filesystem -t ghcr.io/<you>/advise_filesystem:0.1.0
sudo ig run ghcr.io/<you>/advise_filesystem:0.1.0 --containername my-app
```

`ig image build` compiles the eBPF + WASM without root; store writes and `ig run`
(eBPF load) need root. See `dev.md`.

## Attribution / licensing

- `program.bpf.c` adapts the openat enter/exit tracing + full-path resolution
  from IG's `trace_open` (GPL-2.0) and the per-mntns aggregation from
  `advise_seccomp`. **GPL-2.0** (GPL-restricted BPF helpers).
- `go/` (WASM operator + `advice` package) is **Apache-2.0**, matching IG.

## Limitations

- A path the workload never mutated in the window is invisible
  (dynamic-observation floor — a signal, not a proof; grade confidence before
  enforcing). Timestamp-only updates (`utimes`) and opens issued through
  `openat2(2)` or io_uring are not traced (io_uring *metadata* ops are covered —
  the LSM hooks fire regardless of entry point).
- Metadata-mutation coverage needs `CONFIG_SECURITY_PATH=y` (implied by
  AppArmor/TOMOYO/Landlock — all major distros); without it the
  `security_path_*` kprobes cannot attach and the gadget fails to start.
- tmpfs is derived at directory granularity from written files. Volume vs tmpfs
  correlation (does a written dir belong to a mount?) is intentionally left to
  downstream tooling, which can see the container's mounts.
- If an eBPF map fills during the run, dropped observations are counted and a
  `# WARNING` comment is appended to the advice — treat such a result as
  incomplete.
