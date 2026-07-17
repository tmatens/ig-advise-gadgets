// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package tests holds the gadget-level test for advise_filesystem.
//
// SCAFFOLD: mirrors Inspektor Gadget's advise_seccomp unit test, which drives
// the real gadget through the IG gadgetrunner harness and requires that harness
// plus eBPF privileges (CAP_BPF/CAP_PERFMON). It is left as a documented
// skeleton; the pure aggregation is covered host-side by go/advice, and the live
// signal by test/e2e.sh.
//
// The assertion the real harness test must make: a process that writes to
// /dir/file yields an `advise` packet containing "read_only: true" and a tmpfs
// entry for "/dir", and does not list directories that were only read.
package tests

import "testing"

func TestAdviseFilesystemGadget(t *testing.T) {
	t.Skip("scaffold: requires the Inspektor Gadget gadgetrunner harness and eBPF privileges; see test/e2e.sh and go/advice for runnable coverage")
}
