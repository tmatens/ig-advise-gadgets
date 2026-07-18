// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package advice

import (
	"strings"
	"testing"
)

func TestTmpfsDirs(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		dirs  []string
		want  []string
	}{
		{"empty", nil, nil, []string{}},
		{
			"files reduce to parent dirs, deduped + sorted",
			[]string{
				"/var/run/postgresql/.s.PGSQL.5432.lock",
				"/var/run/postgresql/.s.PGSQL.5432",
				"/var/log/postgresql/postgresql.log",
			},
			nil,
			[]string{"/var/log/postgresql", "/var/run/postgresql"},
		},
		{"relative and empty paths ignored", []string{"", "relative/x", "/tmp/a"}, nil, []string{"/tmp"}},
		{"trailing-slash normalized", []string{"/data/foo/"}, nil, []string{"/data"}},
		{
			// A directory-entry mutation (mkdir/unlink/rename) is recorded
			// against the parent dir itself: the path IS the writable dir,
			// not its parent.
			"dir mutations kept as-is, not parent-reduced",
			nil,
			[]string{"/var/cache/app"},
			[]string{"/var/cache/app"},
		},
		{
			"file and dir mutations on the same dir dedupe to one entry",
			[]string{"/var/lib/app/data.txt"},
			[]string{"/var/lib/app"},
			[]string{"/var/lib/app"},
		},
		{"relative and empty dir paths ignored", nil, []string{"", "rel/dir", "/opt/x/"}, []string{"/opt/x"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TmpfsDirs(tc.files, tc.dirs)
			if !equal(got, tc.want) {
				t.Errorf("TmpfsDirs(%v, %v) = %v, want %v", tc.files, tc.dirs, got, tc.want)
			}
			if !isSorted(got) {
				t.Errorf("result not sorted: %v", got)
			}
		})
	}
}

func TestRenderAlwaysReadOnly(t *testing.T) {
	for _, paths := range [][]string{nil, {"/tmp/x"}, {"/a/b", "/c/d"}} {
		out := Render("c", paths, nil)
		if !strings.Contains(out, "securityContext:\n  readOnlyRootFilesystem: true") {
			t.Errorf("Render(%v) missing readOnlyRootFilesystem: true:\n%s", paths, out)
		}
	}
}

func TestRenderNoWritesHasNoWritablePaths(t *testing.T) {
	out := Render("app", nil, nil)
	if strings.Contains(out, "writable_paths:") {
		t.Errorf("no writes should not emit writable_paths:\n%s", out)
	}
	if !strings.Contains(out, "needs no writable paths") {
		t.Errorf("no writes should note none required:\n%s", out)
	}
}

func TestRenderWritablePathsBlock(t *testing.T) {
	// Mixed input: two file writes and one mkdir-style dir mutation.
	out := Render("my-app", []string{"/var/run/x/f", "/var/run/x/g", "/tmp/h"},
		[]string{"/var/cache/app"})
	if !strings.HasPrefix(out, "# my-app\n") {
		t.Errorf("expected container comment header:\n%s", out)
	}
	// dirs deduped (/var/run/x once) and sorted: /tmp < /var/cache < /var/run
	want := "writable_paths:\n  - /tmp\n  - /var/cache/app\n  - /var/run/x\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected sorted deduped writable_paths block %q in:\n%s", want, out)
	}
	// The persistence caveat must be present so users don't tmpfs a path that
	// should be a persistent volume.
	if !strings.Contains(out, "survive") {
		t.Errorf("expected persistence caveat in:\n%s", out)
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

func TestRenderPathInjectionEscaped(t *testing.T) {
	// A write-intent open under a directory whose name embeds a newline + a YAML
	// key must NOT produce a new top-level YAML node.
	out := Render("app", []string{"/tmp/x\nprivileged: true/f"}, nil)
	for _, line := range strings.Split(out, "\n") {
		if line == "privileged: true" {
			t.Fatalf("injected top-level key reached output:\n%s", out)
		}
	}
	if !strings.Contains(out, `\n`) {
		t.Fatalf("newline in path was not escaped:\n%s", out)
	}
	// The dir-mutation input renders through the same escaper.
	out = Render("app", nil, []string{"/tmp/y\nprivileged: true"})
	for _, line := range strings.Split(out, "\n") {
		if line == "privileged: true" {
			t.Fatalf("injected top-level key via dir path reached output:\n%s", out)
		}
	}
}

func TestRenderCommentInjectionSanitized(t *testing.T) {
	out := Render("app\ncap_add: [SYS_ADMIN]", nil, nil)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "cap_add:") {
			t.Fatalf("newline in container name broke out of the comment:\n%s", out)
		}
	}
}

func TestRenderPlainPathUnquoted(t *testing.T) {
	out := Render("", []string{"/var/lib/app/data.txt"}, nil)
	if !strings.Contains(out, "  - /var/lib/app\n") {
		t.Fatalf("ordinary path should stay unquoted for readability:\n%s", out)
	}
}
