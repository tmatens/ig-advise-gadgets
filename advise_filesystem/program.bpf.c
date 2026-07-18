// SPDX-License-Identifier: GPL-2.0
//
// advise_filesystem — record the rootfs paths a container mutates, per
// container, so a read-only-rootfs + tmpfs recommendation can be derived. Two
// signals feed one aggregation map: write-intent open()s (openat enter/exit
// pairing via a `start` scratch map, full-path resolution — adapted from
// Inspektor Gadget's trace_open gadget) and metadata-only mutations (mkdir,
// unlink, rename, … — observed at the security_path_* LSM hooks, see the
// section comment below). The per-mntns aggregation map + GADGET_MAPITER
// pattern follows advise_seccomp.
//
// Copyright 2019 Facebook
// Copyright 2020 Netflix
// Copyright 2026 ig-advise-gadgets authors
//
// This program uses GPL-restricted BPF helpers; the license string must be GPL.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/filesystem.h> // read_full_path_of_open_file_fd, GADGET_PATH_MAX
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

// open(2) flags (octal in the kernel). Defined locally to avoid depending on
// their presence in vmlinux.h.
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100
#define O_TRUNC 00001000
#define O_APPEND 00002000

// write_intent reports whether an open() flags value implies the file may be
// written (as opposed to a pure O_RDONLY open).
static __always_inline bool write_intent(int flags)
{
	if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR)
		return true;
	if (flags & (O_CREAT | O_TRUNC | O_APPEND))
		return true;
	return false;
}

// Runtime-setup ("runc") noise is not special-cased by process name here; see
// the rationale in advise_capabilities/program.bpf.c. Under --containername, ig's
// container-registration boundary already excludes the runtime's setup writes.

struct fkey {
	gadget_mntns_id mntns_id_raw;
	char path[GADGET_PATH_MAX];
};

struct fval {
	// File-level write events for this (container, path): write-intent opens
	// plus non-open file mutations (truncate, chmod, chown). The advice layer
	// derives the writable directory as the path's parent.
	__u32 count;
	// Directory-entry mutations (mkdir, rmdir, unlink, rename, symlink, link,
	// mknod) recorded against the parent directory itself: the path IS the
	// directory that must be writable, no parent derivation needed.
	__u32 dir_writes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct fkey);
	__type(value, struct fval);
	__uint(max_entries, 8192);
} writes_per_mntns SEC(".maps");

GADGET_MAPITER(files, writes_per_mntns);

// fkey is 520 bytes — too large for the 512-byte BPF stack — so build it in a
// per-CPU scratch map instead of on the stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fkey);
} keybuf SEC(".maps");

struct args_t {
	int flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct args_t);
} start SEC(".maps");

// An advisor must not silently under-report: a failed map insert means the
// recommendation is missing a path the workload wrote. Count every such
// failure; the WASM operator surfaces a warning when non-zero.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 z = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &z);
	if (d)
		__sync_fetch_and_add(d, 1);
}

static __always_inline int trace_enter(int flags)
{
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	struct args_t args = {};

	if (gadget_should_discard_data_current())
		return 0;
	if (!write_intent(flags))
		return 0;

	args.flags = flags;
	if (bpf_map_update_elem(&start, &pid, &args, BPF_ANY))
		count_drop(); // start map full: the exit probe will miss this open
	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_enter_open")
int ig_fs_open_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((int)ctx->args[1]);
}
#endif

SEC("tracepoint/syscalls/sys_enter_openat")
int ig_fs_openat_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((int)ctx->args[2]);
}

static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	struct args_t *ap;
	struct fkey *k;
	struct fval zero = {};
	struct fval *v;
	__u32 z = 0;
	long ret;

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;
	ret = ctx->ret;
	if (ret < 0)
		goto cleanup; // open failed: nothing was actually written to

	k = bpf_map_lookup_elem(&keybuf, &z);
	if (!k)
		goto cleanup;
	__builtin_memset(k, 0, sizeof(*k));
	k->mntns_id_raw = gadget_get_current_mntns_id();

	// Resolve the absolute, symlink-followed path of the fd we just opened.
	if (read_full_path_of_open_file_fd((int)ret, k->path, sizeof(k->path)) <= 0)
		goto cleanup;
	if (k->path[0] == '\0')
		goto cleanup;

	v = bpf_map_lookup_or_try_init(&writes_per_mntns, k, &zero);
	if (v)
		__sync_fetch_and_add(&v->count, 1);
	else
		count_drop(); // aggregation map full: this write path is lost

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_exit_open")
int ig_fs_open_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}
#endif

SEC("tracepoint/syscalls/sys_exit_openat")
int ig_fs_openat_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

// ---------------------------------------------------------------------------
// Metadata mutations. mkdir, rmdir, unlink, rename, symlink, link, mknod,
// truncate, chmod and chown mutate the filesystem without opening a file for
// write, so the open tracepoints above never see them — yet a read-only rootfs
// blocks them all. They are observed at the path-based LSM hooks
// (security_path_*), which exist on any kernel built with CONFIG_SECURITY_PATH
// (implied by AppArmor, TOMOYO and Landlock — enabled on all major distros).
// Hooking the LSM layer instead of per-syscall tracepoints covers every entry
// point (including io_uring) with one program per operation, and hands us the
// parent directory as a struct path that get_path_str() resolves to the
// container-view absolute path.
//
// Semantics: the hook fires after path lookup but before the operation
// executes, so this records *attempts* that passed lookup — same conservative
// "write intent" stance as the open side. For directory-entry mutations the
// written object is the parent directory's contents, so the parent itself is
// recorded (dir_writes); file-level mutations (truncate/chmod/chown) record
// the file (count), matching the open side's per-file rows.

static __always_inline int record_path_write(struct path *p, bool dir_write)
{
	struct fkey *k;
	struct fval zero = {};
	struct fval *v;
	__u32 z = 0;
	char *pathstr;

	if (gadget_should_discard_data_current())
		return 0;

	k = bpf_map_lookup_elem(&keybuf, &z);
	if (!k)
		return 0;
	__builtin_memset(k, 0, sizeof(*k));
	k->mntns_id_raw = gadget_get_current_mntns_id();

	pathstr = get_path_str(p);
	if (!pathstr)
		return 0;
	if (bpf_probe_read_kernel_str(k->path, sizeof(k->path), pathstr) <= 0)
		return 0;
	if (k->path[0] == '\0')
		return 0;

	v = bpf_map_lookup_or_try_init(&writes_per_mntns, k, &zero);
	if (!v) {
		count_drop(); // aggregation map full: this mutation is lost
		return 0;
	}
	if (dir_write)
		__sync_fetch_and_add(&v->dir_writes, 1);
	else
		__sync_fetch_and_add(&v->count, 1);
	return 0;
}

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(ig_fs_mkdir, const struct path *dir)
{
	return record_path_write((struct path *)dir, true);
}

SEC("kprobe/security_path_rmdir")
int BPF_KPROBE(ig_fs_rmdir, const struct path *dir)
{
	return record_path_write((struct path *)dir, true);
}

SEC("kprobe/security_path_unlink")
int BPF_KPROBE(ig_fs_unlink, const struct path *dir)
{
	return record_path_write((struct path *)dir, true);
}

SEC("kprobe/security_path_symlink")
int BPF_KPROBE(ig_fs_symlink, const struct path *dir)
{
	return record_path_write((struct path *)dir, true);
}

SEC("kprobe/security_path_mknod")
int BPF_KPROBE(ig_fs_mknod, const struct path *dir)
{
	return record_path_write((struct path *)dir, true);
}

// security_path_link(old_dentry, new_dir, new_dentry): the mutated directory
// is the link's destination, the second argument.
SEC("kprobe/security_path_link")
int BPF_KPROBE(ig_fs_link, struct dentry *old_dentry, const struct path *new_dir)
{
	return record_path_write((struct path *)new_dir, true);
}

// A rename mutates both the source and the destination directory.
SEC("kprobe/security_path_rename")
int BPF_KPROBE(ig_fs_rename, const struct path *old_dir, struct dentry *old_dentry,
	       const struct path *new_dir)
{
	record_path_write((struct path *)old_dir, true);
	return record_path_write((struct path *)new_dir, true);
}

SEC("kprobe/security_path_truncate")
int BPF_KPROBE(ig_fs_truncate, const struct path *path)
{
	return record_path_write((struct path *)path, false);
}

SEC("kprobe/security_path_chmod")
int BPF_KPROBE(ig_fs_chmod, const struct path *path)
{
	return record_path_write((struct path *)path, false);
}

SEC("kprobe/security_path_chown")
int BPF_KPROBE(ig_fs_chown, const struct path *path)
{
	return record_path_write((struct path *)path, false);
}

char LICENSE[] SEC("license") = "GPL";
