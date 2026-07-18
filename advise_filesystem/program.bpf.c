// SPDX-License-Identifier: GPL-2.0
//
// advise_filesystem — record the rootfs paths a container opens with WRITE
// intent, per container, so a read-only-rootfs + tmpfs recommendation can be
// derived. The open tracing (openat enter/exit pairing via a `start` scratch
// map, full-path resolution) is adapted from Inspektor Gadget's trace_open
// gadget; the per-mntns aggregation map + GADGET_MAPITER pattern follows
// advise_seccomp.
//
// Copyright 2019 Facebook
// Copyright 2020 Netflix
// Copyright 2026 ig-advise-gadgets authors
//
// This program uses GPL-restricted BPF helpers; the license string must be GPL.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

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
	__u32 count; // number of write-intent opens seen for this (container, path)
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

char LICENSE[] SEC("license") = "GPL";
