// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// Package tests holds the gadget-level test for advise_capabilities.
//
// SCAFFOLD: this mirrors the structure of Inspektor Gadget's advise_seccomp
// unit test (gadgets/advise_seccomp/test/unit), which drives the real gadget
// through the IG gadgetrunner harness and therefore requires:
//   - the IG unit-test harness (github.com/inspektor-gadget/inspektor-gadget/...),
//     available in-tree; out-of-tree it needs the module wired as a test dep, and
//   - privileges to load eBPF (CAP_BPF/CAP_PERFMON).
//
// It is intentionally left as a documented skeleton: the assertion the real test
// must make is that a process which exercises capability C in container X yields
// an `advise` packet for X whose cap_add list contains C and nothing it did not
// use. Wire the harness (or promote in-tree upstream) to enable it.
package tests

import "testing"

func TestAdviseCapabilitiesGadget(t *testing.T) {
	t.Skip("scaffold: requires the Inspektor Gadget gadgetrunner unit-test harness and eBPF privileges; see file header and dev.md")

	// Intended shape (see advise_seccomp/test/unit for the full pattern):
	//
	//   runner := utilstest.NewRunnerWithTest(t, cfg)
	//   opts := gadgetrunner.NewOpts("advise_capabilities", image, ...)
	//   // exercise a capability inside the runner's mount namespace, e.g. a
	//   // setpriority() that forces a CAP_SYS_NICE check, then run the gadget and
	//   // assert the emitted `advise` text contains "SYS_NICE" under cap_add and
	//   // omits capabilities that were never checked.
}
