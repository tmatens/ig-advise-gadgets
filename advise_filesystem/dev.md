# Developing advise_filesystem

## Layout

```
program.bpf.c   eBPF: openat enter/exit → write-intent path → per-(mntns,path) map (GADGET_MAPITER)
gadget.yaml     datasources (files + advise) and field annotations
build.yaml      wasm: go/program.go
go/program.go   WASM operator: group rows by container → read_only + tmpfs advice
go/advice/      pure write-paths → tmpfs-dirs logic (host-unit-tested, no wasmapi)
test/e2e.sh     root-gated end-to-end (a file-writing container → read_only + tmpfs dir)
test/unit/      IG gadgetrunner harness test (skeleton; needs harness + privileges)
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
```

Keep `go/go.mod`'s IG pin in lockstep with the repo-root `IG_VERSION` file.
Upstreaming: swap to the in-tree `module main` + replace form and move
aggregation to a core `generate_*` operator (see advise_networkpolicy).
