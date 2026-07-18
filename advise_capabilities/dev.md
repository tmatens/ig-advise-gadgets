# Developing advise_capabilities

## Layout

```
program.bpf.c   eBPF: cap_capable kprobe/kretprobe → per-mntns held-cap bitmap (GADGET_MAPITER)
gadget.yaml     datasources (capabilities + advise) and field annotations
build.yaml      wasm: go/program.go
go/program.go   WASM operator: bitmap → cap_drop/cap_add advice, one packet per container
go/go.mod       out-of-tree module pin (github.com/inspektor-gadget/inspektor-gadget)
test/unit/      IG gadgetrunner harness test (own module; runs the real gadget, needs root)
```

## Build

```sh
# Compiles eBPF (amd64+arm64) and the Go→wasip1 WASM operator. -o writes the
# generated objects to a folder; this step does NOT need root.
ig image build . -t advise_capabilities:dev -o ./out

# The final tag/store step writes /var/lib/ig/oci-store and DOES need root.
# One-time fix to build+push as your user:
sudo install -d -o "$USER" /var/lib/ig
```

If the WASM step reports `missing go.sum entry`, run `cd go && go mod tidy` once
(needs network) to populate `go/go.sum`, then rebuild.

## Gadget-level unit test

`test/unit` drives the built image through IG's gadgetrunner harness
in-process — the same pattern as the in-tree `advise_seccomp` unit test. It
needs root (eBPF) and the image in the local OCI store; the image name is
resolved from `GADGET_REPOSITORY`/`GADGET_TAG`:

```sh
ig image build . -t advise_capabilities:dev
(cd test/unit && GADGET_TAG=dev IG_VERIFY_IMAGE=false go test -v -exec 'sudo -E' ./...)
```

`test/unit` is its own Go module: IG's `pkg/testing` packages are a heavy
dependency tree kept out of the WASM module, and out-of-tree consumers must
mirror the two `replace` directives from inspektor-gadget's go.mod (see the
comment in `test/unit/go.mod`).

## Version pinning

`go/go.mod` pins `github.com/inspektor-gadget/inspektor-gadget` — keep it in
lockstep with the repo-root `IG_VERSION` file. Bumping the IG pin means bumping
here and rebuilding.

## Running

`ig run` loads eBPF and needs root (`CAP_BPF` + `CAP_PERFMON`). The gadget honors
IG container selection (`--containername`, mntns filter) via
`gadget_should_discard_data_current()` and the `mntns_filter` map.

## Upstreaming

To move in-tree, swap the `go/go.mod` require for the in-tree replace directive
(commented there) and relocate the aggregation from the WASM operator to a core
`generate_*` operator per `advise_networkpolicy`. Track upstream issue #173.
