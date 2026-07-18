# advise_filesystem — internals

A function-by-function walkthrough of how the gadget works. The
[`README.md`](README.md) covers *what* it is and how to run it; this document
covers *how* it works and *why* each piece is the way it is. File references are
by function/section name rather than line number so they survive edits.

## What it computes

For each observed container, the set of rootfs paths the workload **mutated**
— files opened with write intent (reduced to their parent directories) plus
directories whose entries were changed by metadata-only operations (`mkdir`,
`unlink`, `rename`, …) — i.e. the writable carve-outs a read-only root
filesystem would need:

```yaml
# my-app
securityContext:
  readOnlyRootFilesystem: true
# writable directories the workload needs; the front-end maps these to
# tmpfs / emptyDir, or a persistent volume where a path must survive:
writable_paths:
  - /var/lib/app
  - /var/run
```

## Pipeline at a glance

```
open(2) / openat(2) syscalls                     metadata mutations (mkdir,
  │                                              unlink, rename, symlink, link,
  ├─ sys_enter_open{,at} tracepoint              mknod, truncate, chmod, chown)
  │    filter → write_intent(flags)? → stash       │
  └─ sys_exit_open{,at}  tracepoint                └─ security_path_* LSM kprobes
       open succeeded? → resolve path                   filter → resolve parent-dir
       from the returned fd → count                     (or file) struct path →
       under (mntns, path)                              count under (mntns, path)
  ▼                                                ▼
writes_per_mntns  (BPF hash: {mntns, path[512]} → {count, dir_writes})
  │   GADGET_MAPITER → "files" datasource, flushed ONCE at gadget stop
  ▼
WASM operator (go/program.go)   group rows by container, split files vs dirs
  ▼
advice package (go/advice)      files → parent dirs, dirs as-is → escaped YAML
  ▼
"advise" datasource             one text packet per container
```

Two halves, deliberately split: the **eBPF half** records the smallest
sufficient signal (one map row per distinct written path per container); the
**WASM half** is a thin adapter around a pure, host-unit-testable `advice`
package. Opinionated judgement — volume-vs-tmpfs correlation, confidence
grading, output formats beyond the neutral list — is intentionally not here;
see the scoping note in the top-level [`README.md`](../README.md).

## The eBPF half (`program.bpf.c`)

### Why syscall tracepoints (not kprobes)

`sys_enter_openat` / `sys_exit_openat` are a **stable kernel ABI** — unlike VFS
kprobes, they cannot drift across kernel versions — and they are exactly what
upstream IG's `trace_open` (which this program is adapted from) uses. The
`open(2)` variants are guarded by `#ifndef __TARGET_ARCH_arm64` because arm64
never had the legacy `open` syscall — only `openat` exists there.

### `write_intent(flags)` — what counts as a write

```c
if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR)
        return true;
if (flags & (O_CREAT | O_TRUNC | O_APPEND))
        return true;
```

- The access mode covers ordinary writes — including `mmap` writes, since a
  shared writable mapping requires the file to be opened `O_RDWR`.
- `O_CREAT` and `O_TRUNC` are filesystem *mutations even with `O_RDONLY`*:
  creating a file writes to its directory, truncation writes to the file. A
  read-only rootfs would refuse both, so they must be observed.
- `O_APPEND` alongside `O_RDONLY` is meaningless but harmless to include —
  the check is deliberately conservative toward "write".

The flag constants are defined locally (kernel octal values) rather than
relying on their presence in `vmlinux.h`.

### Entry side (`trace_enter`)

Filters first (`gadget_should_discard_data_current()` — IG's mntns-based
container scoping, kernel-side; then `write_intent`), then stashes `{flags}`
in the `start` map keyed by the thread id (`(u32)bpf_get_current_pid_tgid()`,
the low half = the tid, unique per thread — a thread has at most one open in
flight). A failed insert calls `count_drop()` — see
[the drops contract](#the-drops-contract).

Why stash at all? The decision to *record* needs the exit side (did the open
succeed? what fd?), but the *flags* are only an argument on the enter side.
The stash also acts as the marker "this thread's in-flight open had write
intent", so the exit probe does nothing for read-only opens.

### Exit side (`trace_exit`) — resolve the path from the fd

```c
ap = bpf_map_lookup_elem(&start, &pid);     // paired write-intent open?
if (ctx->ret < 0) goto cleanup;             // ① failed open — nothing written
k = bpf_map_lookup_elem(&keybuf, &z);       // ② per-CPU scratch, not stack
__builtin_memset(k, 0, sizeof(*k));         // ③ zero — key equality depends on it
k->mntns_id_raw = gadget_get_current_mntns_id();
read_full_path_of_open_file_fd((int)ret, k->path, sizeof(k->path));  // ④
v = bpf_map_lookup_or_try_init(&writes_per_mntns, k, &zero);
if (v) __sync_fetch_and_add(&v->count, 1);
else count_drop();
cleanup: bpf_map_delete_elem(&start, &pid); // always
```

① A failed open created/truncated/wrote nothing (`O_CREAT|O_EXCL` that fails
creates no file), so it must not generate advice.

② `struct fkey` is 8 + 512 = **520 bytes — larger than the 512-byte BPF
stack**. It is built in `keybuf`, a 1-entry `PERCPU_ARRAY`. This is safe
without locking because the program runs to completion on one CPU without
sleeping (tracepoint programs are non-preemptible in this sense), so no other
user of the same CPU's slot can interleave — the standard BPF scratch-buffer
pattern, also used inside IG's own `filesystem.h`.

③ The `memset` matters for correctness, not hygiene: the whole 520-byte key is
hashed, so identical `(mntns, path)` pairs must be byte-identical — stale
bytes after a shorter path would split one logical key into many.

④ `read_full_path_of_open_file_fd` (IG's `<gadget/filesystem.h>`, adapted from
Tracee) takes the **fd the syscall just returned**, follows it to the kernel's
`struct file`, and walks the dentry chain upward — crossing mount points —
until the root of the opener's mount namespace. Resolving from the fd rather
than reading the syscall's path argument gets the *canonical* path: symlinks
followed, `dirfd`-relative paths and `..` resolved, and expressed in the
**container's view** of the filesystem (its mntns root) — which is the right
frame for rootfs advice. The trade-off: paths deeper than `GADGET_PATH_MAX`
(512 bytes) or more than 80 components are truncated/unresolvable and the row
is skipped or clipped — pathological for real workloads, but worth knowing.

### Maps

| Map | Type | Size | Role | On overflow |
|---|---|---|---|---|
| `writes_per_mntns` | hash: `{mntns, path[512]}` → `{count, dir_writes}` | 8192 | the aggregate; one row per distinct mutated path per container (`count` = file-write events, `dir_writes` = directory-entry mutations) | `count_drop()` — path lost, loudly |
| `keybuf` | 1-entry per-CPU array of `fkey` | 1 | 520-byte key scratch (stack limit) | n/a |
| `start` | hash: tid → `{flags}` | 10240 | enter→exit marker + flags | `count_drop()` — one open missed, loudly |
| `drops` | 1-entry array of u64 | 1 | failed-insert counter | n/a |

8192 distinct written paths across all observed containers is generous for the
target workloads (server containers write to a handful of directories); the
map stores *distinct* paths, not events — repeated writes only bump `count`.

### Metadata mutations — the `security_path_*` kprobes

`mkdir`, `rmdir`, `unlink`, `rename`, `symlink`, `link`, `mknod`, `truncate`,
`chmod` and `chown` mutate the filesystem **without opening a file for
write**, yet a read-only rootfs blocks them all — pure open-tracing would
advise a read-only rootfs that breaks a mkdir-only workload. These are
observed at the **path-based LSM hooks** (`security_path_mkdir` & co.) via
kprobes, with a shared `record_path_write(path, dir_write)` helper.

Why the LSM layer instead of more syscall tracepoints:

- **One hook per operation, every entry point.** `unlink` alone has two
  syscalls (`unlink`, `unlinkat`) plus io_uring; the LSM hook is downstream of
  all of them, so io_uring metadata ops are covered for free.
- **The hook hands us a resolved `struct path`** of the parent directory,
  which `get_path_str()` turns into the canonical container-view absolute
  path — no user-string/`dirfd` resolution problem, the same quality of path
  the open side gets from its fd.
- **Availability**: the hooks exist on kernels built with
  `CONFIG_SECURITY_PATH=y`, which is implied by AppArmor, TOMOYO and Landlock
  — enabled on every major distro. On a kernel without it the kprobes cannot
  attach and the gadget fails to start (loudly, not silently under-reporting).

Two semantic points, both deliberate:

- **The parent directory is recorded as the written object** (`dir_writes`).
  A directory-entry mutation writes the *directory's contents*, so the
  writable carve-out is the directory itself — the advice layer must not take
  its parent. That is why the map value distinguishes `dir_writes` from
  file-level `count` (truncate/chmod/chown record the file, like the open
  side, and reduce to the parent). A rename records **both** the source and
  destination directories.
- **Attempts, not completions.** The hook fires after path lookup but before
  the operation executes, so a mutation that later fails (quota, LSM denial)
  still counts — the same conservative write-*intent* stance as the open
  side, erring toward a writable dir that wasn't strictly needed rather than
  missing one that was.

### The drops contract

An advisor must not silently under-report: a lost observation here means a
directory missing from `writable_paths`, and enforcing the advice would break
the workload at runtime. Every failed insert increments the `drops` counter;
the WASM operator reads it at flush, warns, and appends `# WARNING: N
observation(s) dropped … recommendation may be incomplete` to **every** advice
packet (global counter — attribution is ambiguous, so all output is marked).

## The datasource contract (`gadget.yaml`)

- `GADGET_MAPITER(files, writes_per_mntns)` exposes the aggregate as the
  `files` datasource.
- `ebpf.map.flush-on-stop: true` + `operator.oci.ebpf.map-fetch-interval: "0"`
  give advisor semantics: the map is iterated exactly once, at stop, so the
  WASM subscription sees the whole run's data in one batch.
- `cli.supported-output-modes: none` keeps the raw rows off the CLI; the
  `advise` datasource is the CLI-facing output (mode `advise`, raw text — the
  `advise_seccomp` convention).
- `mntns_id_raw` is typed `gadget_mntns_id`, which is what lets IG enrich each
  row with `runtime.containerName` / `k8s.containerName`.

## The WASM half (`go/program.go`)

`gadgetInit` creates the `advise` output datasource (`DataSourceTypeSingle`,
one `text` field). `gadgetPreStart` resolves the `files` datasource + field
handles (any failure aborts the run — a schema mismatch is a hard error) and
subscribes with `SubscribeArray(…, 9999)`: low priority (high number) so it
runs after IG's built-in operators — notably container-name enrichment — have
processed the batch.

Unlike `advise_capabilities` (one map row per container), the map iterator
here delivers one row per **(container, path)**, so the callback:

1. Filters each row — `api.ShouldDiscardMntNsID` (belt-and-braces on top of
   the kernel-side filter), empty paths skipped.
2. **Groups rows by mntns id**, capturing the container name from the first
   row of each group (`k8s.containerName`, falling back to
   `runtime.containerName` for plain-Docker runs), and **splits each row into
   the file list or the dir list** on `dir_writes > 0` (a path cannot be both
   a written file and a mutated directory; dir takes precedence as the
   broader carve-out).
3. Emits packets sorted by mntns id, so multi-container output is
   deterministic run-to-run.
4. Each packet: `advice.Render(name, files, dirs) +
   advice.OverflowWarning(dropped)`, with `dropped` read once per flush from
   the `drops` map via `api.GetMap`.

## The advice package (`go/advice`)

Pure Go, no `wasmapi` import — unit-testable on the host.

- `TmpfsDirs` — merge the two inputs into one writable-directory set: written
  *files* reduce to their parent directory (`path.Dir(path.Clean(p))`),
  mutated *directories* are kept as-is (`path.Clean(d)` — the path already IS
  the writable dir), then deduplicate and sort. Directory granularity because
  that is what the enforcement mechanisms take: Compose `tmpfs:` and k8s
  `emptyDir` mount a directory, not a file. Parent/child dirs are *not*
  merged (`/var/lib/app` and `/var/lib/app/cache` may both appear) — collapsing
  them is a policy choice (mount the parent as one tmpfs vs two mounts) left to
  the front-end. Non-absolute or empty paths are ignored defensively; the eBPF
  side only ever produces absolute ones.
- `Render` — invariants: `readOnlyRootFilesystem: true` is unconditional (the
  deny-by-default baseline); with no observed writes an explicit "no writable
  paths" comment is rendered, never an empty `writable_paths:` key; entries
  sorted.
- **Every path goes through `yamlScalar`** (`yaml.go`). This is the security
  boundary of the output: a path is *workload-controlled* data (a Linux path
  may contain any byte except NUL and `/`, including newlines and YAML
  metacharacters), and the advice is YAML that downstream tooling parses and
  applies to container privilege. Without escaping, a container that creates
  `/tmp/x\nprivileged: true` and writes to it would inject a top-level
  `privileged: true` node into its own recommendation — making the advisor
  recommend *more* privilege than observed. `yamlScalar` emits conservative
  path-like strings (alnum plus `/._-+@`, not starting with `-`) as bare
  scalars for readability, and double-quotes-and-escapes everything else
  (`\n`, `\r`, `\t`, `\xNN` for other control bytes, `\\`, `\"`), so no byte
  can terminate the scalar or start a new node.
- `commentText` — the container name is rendered into a `# comment`; comments
  cannot be escaped, only broken by a line break, so control characters are
  replaced with spaces.
- `OverflowWarning` — the drops count as a YAML *comment*, keeping the output
  machine-parseable even when incomplete.

## What the tests pin down

Unit (`go/advice/advice_test.go`): `TmpfsDirs` reduction (files → parent,
dirs kept as-is, mixed dedup, sorting, non-absolute ignored), the Render
invariants, and the YAML-injection cases — a newline-bearing path (via either
input) must render as one quoted scalar, a newline-bearing container name
must stay inside its comment.

E2E (`test/e2e.sh`): builds the image, runs a container that writes a file
under `/var/lib/app` **and only ever mkdir/rmdirs under `/var/cache/app`**,
observes it, and asserts both directories appear under `writable_paths:`. The
`/var/cache/app` assertion is the regression proof for the LSM-hook coverage:
no file is ever opened for write there, so pure open-tracing would miss it.

## Accuracy analysis — where it can be wrong

Over-approximation (recommends more writable surface than strictly needed):

- Write-*intent*, not write-*fact*: a file opened `O_RDWR` but never written
  still counts, and a metadata mutation that fails after the LSM hook (quota,
  MAC denial) still counts. Conservative in the safe direction — advising a
  writable dir that wasn't strictly needed never breaks the workload.
- Writes to already-mounted volumes appear in `writable_paths` too; the
  front-end (which can see the container's mounts) is expected to correlate —
  a written path on a volume should stay a volume, not become tmpfs.

Under-approximation (misses writes — the dangerous direction, hence the loud
overflow design):

- **Observation window** — only what ran is seen; a signal, not a proof.
- **Map overflow** — counted and stamped into the output (`drops`).
- **Timestamp-only updates**: `utimes`/`utimensat` go through
  `notify_change`/`security_inode_setattr` — there is no path-based LSM hook
  for them, so a workload whose only mutation is touching timestamps is
  invisible. Narrow residual gap, documented in the README.
- **Non-tracepoint open paths**: `openat2(2)` (rare from libc — glibc uses
  `openat`) and io_uring's `IORING_OP_OPENAT` bypass the two open
  tracepoints. Note this applies to *opens* only — metadata mutations are
  caught at the LSM layer regardless of entry point, io_uring included.

## Hard questions a reviewer might ask

**Q: Why trace opens at all instead of `fsnotify`/fanotify or comparing
filesystem snapshots?**
Those are userspace mechanisms with per-mount setup and event-loss semantics;
the tracepoint pair is namespace-agnostic, needs no per-container setup,
attributes events to containers via IG's existing mntns machinery, and reuses
the audited `trace_open` code path.

**Q: You argue syscall tracepoints beat kprobes for stability — then attach
kprobes for the metadata operations. Which is it?**
Both, deliberately. For *opens* a stable syscall tracepoint exists and matches
upstream `trace_open`, so it wins. For metadata mutations there is no
tracepoint at the right layer, and covering them syscall-by-syscall would mean
~20 tracepoints that still miss io_uring. The `security_path_*` hooks are the
kernel's own abstraction point for exactly these operations — their signatures
are stable in practice (tracee has hooked them for years), they see every
entry point, and they hand over a resolved `struct path` instead of a user
string. The trade-off taken is the `CONFIG_SECURITY_PATH` requirement, which
AppArmor/TOMOYO/Landlock make near-universal; a kernel without it fails the
kprobe attach loudly rather than under-reporting silently.

**Q: Why resolve the path at exit from the fd instead of reading the
`filename` argument at entry?**
The argument is whatever the process passed: possibly relative (against an
arbitrary `dirfd`), symlinked, or `..`-laden. The fd's dentry walk yields the
canonical absolute path in the container's own mount-namespace view — the
frame the advice needs — and only exists for opens that actually succeeded.

**Q: Two containers write to `/var/run` — do their rows collide?**
No. The map key is `(mntns, path)`, so the same path in different containers
is two rows, and the WASM operator groups by mntns before rendering.

**Q: Is the per-CPU `keybuf` safe against concurrent opens?**
Yes — the buffer is only live within a single program invocation, which runs
to completion on one CPU without sleeping. Two CPUs use two per-CPU slots;
two opens on one CPU serialize.

**Q: Why is the `count` value kept if the advice only uses path presence?**
It is nearly free (the map row exists anyway), it makes the raw `files`
datasource useful to other consumers (hot-path ranking, front-end confidence
grading), and dropping it later is easy while adding it later is not.

**Q: `/tmp` shows up in `writable_paths` — isn't that noise?**
No: it is exactly the finding. A read-only rootfs makes `/tmp` read-only too;
the advice says "this workload needs a writable `/tmp`", which the front-end
turns into a tmpfs mount — the standard hardened pattern.

**Q: Why not emit the file paths and let the front-end compute directories?**
The raw `files` datasource *does* carry file paths for consumers that want
them. The advice layer reduces to directories because that is the enforcement
granularity; doing the reduction in the pure `advice` package keeps it
deterministic and unit-tested once, rather than reimplemented per front-end.

**Q: Could a hostile workload abuse the advice output?**
The interesting attack is YAML injection via crafted path names, which is
exactly what `yamlScalar` closes (see above; regression-tested). Beyond that a
workload can only *inflate* its own writable list by writing more places —
visible, and in the safe direction for correctness of enforcement (though a
front-end should treat an absurdly long list as a red flag, not auto-apply it).
