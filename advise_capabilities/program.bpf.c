// SPDX-License-Identifier: GPL-2.0
//
// advise_capabilities — aggregate the Linux capabilities each container
// actually exercises and expose them per-container for policy advice.
//
// The cap_capable() hooking (kprobe/kretprobe pairing via the `start` scratch
// map, the real-vs-subjective credential guard for overlayfs copy-up) is
// derived from Inspektor Gadget's trace_capabilities gadget:
//   https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.51.0/gadgets/trace_capabilities/program.bpf.c
// The per-mntns aggregation map + GADGET_MAPITER pattern follows advise_seccomp.
//
// Copyright 2024 The Inspektor Gadget authors
// Copyright 2022 Sony Group Corporation
// Copyright 2026 ig-advise-gadgets authors
//
// This program uses GPL-restricted BPF helpers; the license string below must
// stay "GPL".
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns.h>
// Force the mntns filter map to exist so gadget_should_discard_data_current()
// (and the front-end's --containername selection) work.
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

// Linux defines 41 capabilities (CAP_CHOWN=0 .. CAP_CHECKPOINT_RESTORE=40),
// which fit in a single u64 bitmap. cap_capable() is called with the kernel
// capability number, so bit N corresponds to kernel capability N.
#define CAP_MAX 64

// include/linux/security.h
#define CAP_OPT_NOAUDIT (1UL << 1)

extern int LINUX_KERNEL_VERSION __kconfig;

// Runtime-setup ("runc") noise: this gadget does NOT special-case the container
// runtime by process name. Under container-scoped observation (--containername)
// ig's own container-registration boundary already excludes the runtime's setup
// activity — it happens before the container's mount namespace is tracked — so a
// comm-string filter would be a no-op there and a fragile, runtime-specific
// heuristic (runc vs crun vs youki) elsewhere. Explicit setup-noise filtering,
// if wanted for whole-host observation, is deferred to the upstream design
// discussion (issue #173) so it matches how IG handles this for advise_seccomp.

struct key_t {
	gadget_mntns_id mntns_id_raw;
};

struct val_t {
	// Bitmap of held capabilities: bit N set == capability N was checked and
	// the process held it (cap_capable returned 0) at least once.
	__u64 caps;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, 1024);
} caps_per_mntns SEC(".maps");

// Expose the per-container map as an iterable datasource named "capabilities".
// The WASM operator (go/program.go) reads one row per container on stop.
GADGET_MAPITER(capabilities, caps_per_mntns);

const struct val_t blank_val = {};

// cap under check, stashed between kprobe entry and kretprobe exit.
struct args_t {
	int cap;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct args_t);
} start SEC(".maps");

// An advisor must not silently under-report: a failed map insert means the
// final recommendation is missing something the workload exercised. Every such
// failure is counted here; the WASM operator reads the counter at flush and
// surfaces a warning so an incomplete recommendation is never mistaken for a
// complete one.
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

SEC("kprobe/cap_capable")
int BPF_KPROBE(ig_cap_e, const struct cred *cred,
	       struct user_namespace *targ_ns, int cap, int cap_opt)
{
	__u64 pid_tgid;
	struct task_struct *task;
	const struct cred *real_cred;
	struct args_t args = {};

	if (gadget_should_discard_data_current())
		return 0;

	// Ignore checks made with overridden (subjective) credentials — e.g.
	// overlayfs copy-up — which do not reflect the container's real needs.
	task = (struct task_struct *)bpf_get_current_task();
	real_cred = BPF_CORE_READ(task, real_cred);
	if (cred != real_cred)
		return 0;

	// Ignore opportunistic (non-audit) checks — e.g. the CAP_SYS_ADMIN probe
	// in every execve's memory-overcommit accounting. They succeed whenever
	// the capability happens to be held but say nothing about workload need,
	// so recording them would make the advisor recommend a capability an
	// over-privileged container merely possessed (SYS_ADMIN on any exec'ing
	// container). bcc's capable and IG's trace_capabilities hide these by
	// default (upstream issue #173 discussion / PR 914); an advisor must
	// exclude them. Kernels < 5.1 pass `int audit` (1 = audited) instead of
	// CAP_OPT_* flags in the fourth argument.
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
		if (cap_opt & CAP_OPT_NOAUDIT)
			return 0;
	} else {
		if (!cap_opt)
			return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	args.cap = cap;
	if (bpf_map_update_elem(&start, &pid_tgid, &args, BPF_ANY))
		count_drop(); // start map full: the exit probe will miss this check
	return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(ig_cap_x)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct args_t *ap;
	struct val_t *bitmap;
	struct key_t key = {};
	int cap;

	ap = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!ap)
		return 0; // missed entry
	cap = ap->cap;
	bpf_map_delete_elem(&start, &pid_tgid);

	// ret != 0 means the capability was NOT held (a denial). We record only
	// held capabilities — the minimum set the workload actually used.
	if (PT_REGS_RC(ctx) != 0)
		return 0;
	if (cap < 0 || cap >= CAP_MAX)
		return 0;

	key.mntns_id_raw = gadget_get_current_mntns_id();
	bitmap = bpf_map_lookup_or_try_init(&caps_per_mntns, &key, &blank_val);
	if (!bitmap) {
		count_drop(); // aggregation map full: this container's caps are lost
		return 0;
	}

	__sync_fetch_and_or(&bitmap->caps, 1ULL << cap);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
