# Developing advise_devices

## Layout
```
program.bpf.c   eBPF: openat/open exit → resolve fd path → keep /dev/* → per-(mntns,path) map (GADGET_MAPITER)
gadget.yaml     datasources (devices + advise)
build.yaml      wasm: go/program.go
go/program.go   WASM operator: group rows by container → devices grant
go/advice/      pure /dev-paths → non-default devices logic (host unit-tested)
test/e2e.sh     root-gated end-to-end (container opening /dev/fuse → devices grant)
test/unit/      IG gadgetrunner harness test (own module; runs the real gadget, needs root)
```

## Notes
- No enter hook: the opened fd is the syscall return value, so the device path is
  resolved from the fd entirely at exit via read_full_path_of_open_file_fd.
- The 520-byte (mntns,path) key is built in a per-CPU scratch map (BPF stack is 512B).
- The default-device exclusion set (Docker's) lives in go/advice; adjust it there
  for other runtimes.

## Build / test
```sh
ig image build . -t advise_devices:dev
(cd go && go test ./advice/)
sudo IG="$(command -v ig)" bash test/e2e.sh   # needs a host /dev/fuse (or set DEVICE=)

# Gadget-level unit test (gadgetrunner harness; root, host /dev/fuse):
(cd test/unit && GADGET_TAG=dev IG_VERIFY_IMAGE=false go test -v -exec 'sudo -E' ./...)
```

`test/unit` is its own Go module; see the go.mod comment about mirroring IG's
`replace` directives.
