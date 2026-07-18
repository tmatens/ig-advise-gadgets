// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package advice

import (
	"strings"
	"testing"
)

func TestNonDefaultDevices(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"empty", nil, []string{}},
		{"only defaults filtered out", []string{"/dev/null", "/dev/zero", "/dev/urandom"}, []string{}},
		{"pts and shm subtrees filtered", []string{"/dev/pts/0", "/dev/shm/x"}, []string{}},
		{"non-dev paths ignored", []string{"/etc/passwd", "/tmp/f"}, []string{}},
		{
			"non-default devices kept, sorted, deduped",
			[]string{"/dev/fuse", "/dev/dri/card0", "/dev/fuse", "/dev/null"},
			[]string{"/dev/dri/card0", "/dev/fuse"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NonDefaultDevices(tc.paths)
			if !equal(got, tc.want) {
				t.Errorf("NonDefaultDevices(%v) = %v, want %v", tc.paths, got, tc.want)
			}
			if !isSorted(got) {
				t.Errorf("not sorted: %v", got)
			}
		})
	}
}

func TestRenderNoNonDefault(t *testing.T) {
	out := Render("app", []string{"/dev/null", "/dev/urandom"})
	if strings.Contains(out, "  - /dev") {
		t.Errorf("only-default devices should not emit any device entries:\n%s", out)
	}
	if !strings.Contains(out, "no non-default device nodes") {
		t.Errorf("expected note about no grant needed:\n%s", out)
	}
}

func TestRenderDeviceNodes(t *testing.T) {
	out := Render("gpu-app", []string{"/dev/dri/card0", "/dev/null", "/dev/fuse"})
	if !strings.HasPrefix(out, "# gpu-app\n") {
		t.Errorf("expected container comment header:\n%s", out)
	}
	// /dev/null filtered; /dev/dri/card0 and /dev/fuse kept, sorted, raw nodes.
	want := "device_nodes:\n  - /dev/dri/card0\n  - /dev/fuse\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected device_nodes block %q in:\n%s", want, out)
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
