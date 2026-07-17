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

// TmpfsDirs reduces a set of written file paths to the sorted, deduplicated
// parent directories that would need to be writable. tmpfs is applied at
// directory granularity, so this is what a read_only rootfs must carve out.
// Non-absolute or empty paths are ignored.
func TmpfsDirs(writtenPaths []string) []string {
	set := map[string]struct{}{}
	for _, p := range writtenPaths {
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		set[path.Dir(path.Clean(p))] = struct{}{}
	}
	dirs := make([]string, 0, len(set))
	for d := range set {
		dirs = append(dirs, d)
	}
	slices.Sort(dirs)
	return dirs
}

// Render turns a container's observed write-intent paths into a neutral
// read-only-rootfs recommendation: the k8s securityContext field
// readOnlyRootFilesystem plus the writable directories the workload needs. The
// front-end maps writable_paths to the target form (Compose tmpfs:, k8s emptyDir
// volumes, or a persistent volume where a path must survive restarts). With no
// writes it recommends a plain read-only rootfs.
func Render(containerName string, writtenPaths []string) string {
	dirs := TmpfsDirs(writtenPaths)

	var b strings.Builder
	if containerName != "" {
		fmt.Fprintf(&b, "# %s\n", containerName)
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
		fmt.Fprintf(&b, "  - %s\n", d)
	}
	return b.String()
}
