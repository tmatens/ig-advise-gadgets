// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package tests holds the gadget-level test for advise_devices.
//
// SCAFFOLD: mirrors Inspektor Gadget's advise_seccomp harness test, which
// requires the IG gadgetrunner harness and eBPF privileges. The pure default-set
// filtering is covered host-side by go/advice; the live signal by test/e2e.sh.
package tests

import "testing"

func TestAdviseDevicesGadget(t *testing.T) {
	t.Skip("scaffold: requires the Inspektor Gadget gadgetrunner harness and eBPF privileges; see test/e2e.sh and go/advice")
}
