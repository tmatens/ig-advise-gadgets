# Developing advise_filesystem

## Layout

```
program.bpf.c   eBPF: openat enter/exit → write-intent path → per-(mntns,path) map (GADGET_MAPITER)
gadget.yaml     datasources (files + advise) and field annotations
build.yaml      wasm: go/program.go
go/program.go   WASM operator: group rows by container → read_only + tmpfs advice
go/advice/      pure write-paths → tmpfs-dirs logic (host-unit-tested, no wasmapi)
test/e2e.sh     root-gated end-to-end (a file-writing container → read_only + tmpfs dir)
test/unit/      IG gadgetrunner harness test (own module; runs the real gadget, needs root)
```

## Notes

- The map key `struct fkey { mntns_id_raw; char path[512]; }` is 520 bytes, larger
  than the 512-byte BPF stack, so it is assembled in a per-CPU scratch map
  (`keybuf`) rather than on the stack.
- Only successful, write-intent opens are recorded (`O_WRONLY`/`O_RDWR` or
  `O_CREAT`/`O_TRUNC`/`O_APPEND`). Path is the symlink-resolved absolute path via
  `read_full_path_of_open_file_fd`.

## Build / test

```sh
ig image build . -t advise_filesystem:dev            # eBPF + WASM; store write needs root
(cd go && go test ./advice/)                         # pure logic, host, no root
sudo IG="$(command -v ig)" bash test/e2e.sh          # live signal, needs root

# Gadget-level unit test: drives the built image through IG's gadgetrunner
# harness in-process (root for eBPF; image resolved from the local OCI store
# via GADGET_REPOSITORY/GADGET_TAG — here the plain local tag built above):
(cd test/unit && GADGET_TAG=dev IG_VERIFY_IMAGE=false go test -v -exec 'sudo -E' ./...)
```

`test/unit` is its own Go module: IG's `pkg/testing` packages are a heavy
dependency tree kept out of the WASM module, and out-of-tree consumers must
mirror the two `replace` directives from inspektor-gadget's go.mod (see the
comment in `test/unit/go.mod`).

Keep `go/go.mod`'s IG pin in lockstep with the repo-root `IG_VERSION` file.
Upstreaming: swap to the in-tree `module main` + replace form and move
aggregation to a core `generate_*` operator (see advise_networkpolicy).
