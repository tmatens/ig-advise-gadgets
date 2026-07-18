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

// Package advice holds the pure /dev-paths → minimal devices: grant logic, free
// of any wasmapi import so it is unit-testable on the host.
package advice

import (
	"fmt"
	"slices"
	"strings"
)

// defaultDevices are the /dev nodes a container runtime provides by default
// (Docker's default set plus the standard pseudo-devices). Opens of these do
// not require a `devices:` grant and are filtered out of the recommendation.
var defaultDevices = map[string]struct{}{
	"/dev/null": {}, "/dev/zero": {}, "/dev/full": {},
	"/dev/random": {}, "/dev/urandom": {}, "/dev/tty": {},
	"/dev/console": {}, "/dev/ptmx": {}, "/dev/fd": {},
	"/dev/stdin": {}, "/dev/stdout": {}, "/dev/stderr": {},
}

// defaultPrefixes are default /dev subtrees (allocated pts terminals, POSIX
// shared memory / message queues) that never need an explicit grant.
var defaultPrefixes = []string{"/dev/pts/", "/dev/shm/", "/dev/mqueue/"}

// NonDefaultDevices returns the sorted, deduplicated /dev nodes that are NOT
// part of the runtime default set — the ones a minimal `devices:` grant must
// list. Non-/dev or empty paths are ignored.
func NonDefaultDevices(devicePaths []string) []string {
	set := map[string]struct{}{}
	for _, p := range devicePaths {
		if !strings.HasPrefix(p, "/dev/") {
			continue
		}
		if _, ok := defaultDevices[p]; ok {
			continue
		}
		skip := false
		for _, pre := range defaultPrefixes {
			if strings.HasPrefix(p, pre) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		set[p] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// Render turns a container's observed /dev opens into a neutral list of the
// non-default device nodes it needs. The front-end maps these to the target
// form (Compose devices:, docker --device; Kubernetes needs a device plugin, so
// there is no direct securityContext equivalent). Emitting the raw nodes keeps
// that mapping — and any host:container remapping — a front-end concern.
func Render(containerName string, devicePaths []string) string {
	devs := NonDefaultDevices(devicePaths)

	var b strings.Builder
	if containerName != "" {
		fmt.Fprintf(&b, "# %s\n", commentText(containerName))
	}
	if len(devs) == 0 {
		b.WriteString("# no non-default device nodes opened; no device grant required\n")
		return b.String()
	}
	b.WriteString("# non-default device nodes the workload opened; the front-end maps these\n")
	b.WriteString("# to compose devices: / docker --device (k8s requires a device plugin):\n")
	b.WriteString("device_nodes:\n")
	for _, d := range devs {
		fmt.Fprintf(&b, "  - %s\n", yamlScalar(d))
	}
	return b.String()
}

// OverflowWarning renders a YAML-comment warning for n dropped observations
// (0 → ""). Non-empty means an eBPF map filled up during the run, so the
// recommendation may be missing entries the workload needs — treat it as
// incomplete rather than enforcing it.
func OverflowWarning(n uint64) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("# WARNING: %d observation(s) dropped (eBPF map full); recommendation may be incomplete\n", n)
}
