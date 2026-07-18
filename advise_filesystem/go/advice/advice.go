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

// Package advice holds the pure write-paths → read-only-rootfs + tmpfs logic,
// free of any wasmapi import so it is unit-testable on the host. The WASM
// operator (../program.go) is a thin adapter that reads gadget rows and calls
// Render.
package advice

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// TmpfsDirs reduces the observed mutations to the sorted, deduplicated
// directories that would need to be writable. tmpfs is applied at directory
// granularity, so this is what a read_only rootfs must carve out. Two inputs
// with different granularity semantics:
//
//   - writtenFiles are file-level mutations (write-intent opens, truncate,
//     chmod, chown); the writable directory is the file's parent.
//   - writtenDirs are directory-entry mutations (mkdir, unlink, rename, …)
//     recorded against the parent directory itself; the path IS the writable
//     directory.
//
// Non-absolute or empty paths are ignored.
func TmpfsDirs(writtenFiles, writtenDirs []string) []string {
	set := map[string]struct{}{}
	for _, p := range writtenFiles {
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		set[path.Dir(path.Clean(p))] = struct{}{}
	}
	for _, d := range writtenDirs {
		if d == "" || !strings.HasPrefix(d, "/") {
			continue
		}
		set[path.Clean(d)] = struct{}{}
	}
	dirs := make([]string, 0, len(set))
	for d := range set {
		dirs = append(dirs, d)
	}
	slices.Sort(dirs)
	return dirs
}

// Render turns a container's observed mutations (file-level writes plus
// directory-entry mutations, see TmpfsDirs) into a neutral read-only-rootfs
// recommendation: the k8s securityContext field readOnlyRootFilesystem plus
// the writable directories the workload needs. The front-end maps
// writable_paths to the target form (Compose tmpfs:, k8s emptyDir volumes, or
// a persistent volume where a path must survive restarts). With no observed
// mutations it recommends a plain read-only rootfs.
func Render(containerName string, writtenFiles, writtenDirs []string) string {
	dirs := TmpfsDirs(writtenFiles, writtenDirs)

	var b strings.Builder
	if containerName != "" {
		fmt.Fprintf(&b, "# %s\n", commentText(containerName))
	}
	b.WriteString("securityContext:\n  readOnlyRootFilesystem: true\n")
	if len(dirs) == 0 {
		b.WriteString("# no write-intent opens observed; a read-only rootfs needs no writable paths\n")
		return b.String()
	}
	b.WriteString("# writable directories the workload needs; the front-end maps these to\n")
	b.WriteString("# tmpfs / emptyDir, or a persistent volume where a path must survive:\n")
	b.WriteString("writable_paths:\n")
	for _, d := range dirs {
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
