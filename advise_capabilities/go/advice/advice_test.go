// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package advice

import (
	"strings"
	"testing"
)

// canonicalCaps is the authoritative kernel capability order from
// <linux/capability.h> (CAP_CHOWN=0 .. CAP_CHECKPOINT_RESTORE=40), independent
// of the CapNames table under test. If the kernel/IG mapping ever drifts from
// CapNames, this catches it — a wrong index→name mapping would recommend the
// wrong capability, the most dangerous failure this gadget can have.
var canonicalCaps = []string{
	"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
	"KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
	"NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK",
	"IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE",
	"SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE",
	"SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
	"AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
	"WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF",
	"CHECKPOINT_RESTORE",
}

func TestCapNamesMatchKernelOrder(t *testing.T) {
	if len(CapNames) != len(canonicalCaps) {
		t.Fatalf("CapNames has %d entries, kernel defines %d", len(CapNames), len(canonicalCaps))
	}
	for i := range canonicalCaps {
		if CapNames[i] != canonicalCaps[i] {
			t.Errorf("bit %d: CapNames=%q, kernel=%q", i, CapNames[i], canonicalCaps[i])
		}
	}
	// Linux currently defines 41 capabilities (0..40). Guard against silent
	// truncation/extension.
	if len(CapNames) != 41 {
		t.Errorf("expected 41 capabilities, got %d", len(CapNames))
	}
}

func TestHeldCapsDecode(t *testing.T) {
	tests := []struct {
		name   string
		bitmap uint64
		want   []string
	}{
		{"empty", 0, nil},
		{"CHOWN only (bit 0)", 1 << 0, []string{"CHOWN"}},
		{"SYS_ADMIN only (bit 21)", 1 << 21, []string{"SYS_ADMIN"}},
		{"SYS_NICE only (bit 23)", 1 << 23, []string{"SYS_NICE"}},
		{"CHECKPOINT_RESTORE (bit 40, highest)", 1 << 40, []string{"CHECKPOINT_RESTORE"}},
		{
			"postgres-like set",
			(1 << 0) | (1 << 1) | (1 << 3) | (1 << 6) | (1 << 7), // CHOWN,DAC_OVERRIDE,FOWNER,SETGID,SETUID
			[]string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
		},
		{
			"result is sorted regardless of bit order",
			(1 << 21) | (1 << 0), // SYS_ADMIN + CHOWN
			[]string{"CHOWN", "SYS_ADMIN"},
		},
		{"bits above 40 ignored", 1 << 63, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HeldCaps(tc.bitmap)
			if !equal(got, tc.want) {
				t.Errorf("HeldCaps(%#x) = %v, want %v", tc.bitmap, got, tc.want)
			}
			if !isSorted(got) {
				t.Errorf("HeldCaps(%#x) not sorted: %v", tc.bitmap, got)
			}
		})
	}
}

func TestRenderAlwaysDropsAll(t *testing.T) {
	// Every rendering must drop ALL — the whole point of the advisor is a
	// deny-by-default baseline.
	for _, bm := range []uint64{0, 1 << 0, 1<<0 | 1<<23, ^uint64(0)} {
		out := Render("c", bm)
		if !strings.Contains(out, "drop:\n      - ALL") {
			t.Errorf("Render(%#x) missing capabilities drop: ALL:\n%s", bm, out)
		}
		if !strings.Contains(out, "securityContext:\n  capabilities:") {
			t.Errorf("Render(%#x) not a k8s securityContext block:\n%s", bm, out)
		}
	}
}

func TestRenderEmptyHasNoBareAdd(t *testing.T) {
	// A zero bitmap must NOT emit a dangling "add:" with no entries; it must
	// state explicitly that none are required.
	out := Render("app", 0)
	if strings.Contains(out, "add:") {
		t.Errorf("empty bitmap should not emit an add: list:\n%s", out)
	}
	if !strings.Contains(out, "no non-default capabilities observed") {
		t.Errorf("empty bitmap should note none required:\n%s", out)
	}
}

func TestRenderContainerCommentAndCaps(t *testing.T) {
	out := Render("my-postgres", (1<<23)|(1<<0)) // SYS_NICE + CHOWN
	if !strings.HasPrefix(out, "# my-postgres\n") {
		t.Errorf("expected container comment header:\n%s", out)
	}
	// SYS_NICE must appear (regression guard for the SYS_NICE decode, the
	// gadget's headline example) and caps must be listed sorted, k8s-indented.
	wantOrder := "    add:\n      - CHOWN\n      - SYS_NICE\n"
	if !strings.Contains(out, wantOrder) {
		t.Errorf("expected sorted add block %q in:\n%s", wantOrder, out)
	}
}

func TestRenderNoContainerName(t *testing.T) {
	out := Render("", 1<<0)
	if strings.HasPrefix(out, "#") {
		t.Errorf("no container name should omit the comment header:\n%s", out)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isSorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

func TestOverflowWarning(t *testing.T) {
	if got := OverflowWarning(0); got != "" {
		t.Fatalf("OverflowWarning(0) = %q, want empty", got)
	}
	got := OverflowWarning(7)
	if !strings.HasPrefix(got, "# ") {
		t.Fatalf("warning must stay a YAML comment so advice output remains parseable, got %q", got)
	}
	if !strings.Contains(got, "7") || !strings.Contains(got, "incomplete") {
		t.Fatalf("warning missing count or incompleteness wording: %q", got)
	}
}
