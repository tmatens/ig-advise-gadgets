// SPDX-License-Identifier: GPL-2.0
//
// advise_devices — record the /dev/* nodes a container opens, per container, so
// a minimal `devices:` grant can be derived. Path resolution is adapted from
// Inspektor Gadget's trace_open; the per-mntns aggregation + GADGET_MAPITER
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

#include <gadget/filesystem.h> // read_full_path_of_open_file_fd, GADGET_PATH_MAX
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

struct dkey {
	gadget_mntns_id mntns_id_raw;
	char path[GADGET_PATH_MAX];
};

struct dval {
	__u32 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dkey);
	__type(value, struct dval);
	__uint(max_entries, 4096);
} devices_per_mntns SEC(".maps");

GADGET_MAPITER(devices, devices_per_mntns);

// dkey is 520 bytes — larger than the 512-byte BPF stack — so build it in a
// per-CPU scratch map.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dkey);
} keybuf SEC(".maps");

// is_dev_path reports whether path begins with "/dev/". path points into a
// fixed-size map-value buffer, so the constant indexes are in bounds.
static __always_inline bool is_dev_path(const char *path)
{
	return path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
	       path[3] == 'v' && path[4] == '/';
}

// Runtime-setup ("runc") noise is not special-cased by process name here; see
// the rationale in advise_capabilities/program.bpf.c. Under --containername, ig's
// container-registration boundary already excludes the runtime's setup opens.

// The fd being opened is the syscall return value, so the device path can be
// resolved entirely at exit — no enter hook / args stashing is needed.
static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	struct dkey *k;
	struct dval zero = {};
	struct dval *v;
	__u32 z = 0;
	long ret = ctx->ret;

	if (ret < 0)
		return 0;
	if (gadget_should_discard_data_current())
		return 0;

	k = bpf_map_lookup_elem(&keybuf, &z);
	if (!k)
		return 0;
	__builtin_memset(k, 0, sizeof(*k));
	k->mntns_id_raw = gadget_get_current_mntns_id();

	if (read_full_path_of_open_file_fd((int)ret, k->path, sizeof(k->path)) <= 0)
		return 0;
	if (!is_dev_path(k->path))
		return 0;

	v = bpf_map_lookup_or_try_init(&devices_per_mntns, k, &zero);
	if (v)
		__sync_fetch_and_add(&v->count, 1);
	return 0;
}

#ifndef __TARGET_ARCH_arm64
SEC("tracepoint/syscalls/sys_exit_open")
int ig_dev_open_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}
#endif

SEC("tracepoint/syscalls/sys_exit_openat")
int ig_dev_openat_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
