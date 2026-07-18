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
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tests drives the real advise_filesystem gadget end-to-end through
// Inspektor Gadget's gadgetrunner harness (the same pattern as the in-tree
// advise_seccomp unit test): the built gadget image runs in-process, a runner
// thread in its own mount namespace writes a file in one directory and only
// reads from another, and the emitted advise packet is asserted to recommend a
// read-only rootfs with exactly the written directory carved out.
//
// Requires root (eBPF) and the gadget image in the local OCI store; see dev.md
// for the build + invocation (go test -exec 'sudo -E' with GADGET_TAG set).
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const containerName = "test-advise-filesystem"

func TestAdviseFilesystemGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	// Prepared in the test's (host) mount namespace before the gadget runs;
	// the runner's mount namespace is a copy, so the paths are identical.
	writeDir := t.TempDir()
	readDir := t.TempDir()
	seed := filepath.Join(readDir, "seed")
	require.NoError(t, os.WriteFile(seed, []byte("read-only data"), 0o644))

	runner := utilstest.NewRunnerWithTest(t, &utilstest.RunnerConfig{})
	mntnsFilterMap := utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID)

	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utilstest.RunWithRunner(t, runner, func() error {
			// Write intent in writeDir …
			if err := os.WriteFile(filepath.Join(writeDir, "out.txt"), []byte("x"), 0o644); err != nil {
				return err
			}
			// … but only a read in readDir.
			_, err := os.ReadFile(seed)
			return err
		})
		return nil
	}
	opts := gadgetrunner.GadgetRunnerOpts[any]{
		Image:          "advise_filesystem",
		Timeout:        5 * time.Second,
		MntnsFilterMap: mntnsFilterMap,
		OnGadgetRun:    onGadgetRun,
		ParamValues: map[string]string{
			// Advisor semantics: no periodic fetch, flush once on stop.
			"operator.oci.ebpf.map-fetch-count":    "0",
			"operator.oci.ebpf.map-fetch-interval": "0",
		},
	}

	var advices []string
	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
	gadgetRunner.DataOperator = append(gadgetRunner.DataOperator,
		containerNameEnricher(t, "files", runner))
	gadgetRunner.DataFunc = func(ds datasource.DataSource, data datasource.Data) error {
		if ds.Name() != "advise" {
			return nil
		}
		textField := ds.GetField("text")
		require.NotNil(t, textField)
		text, err := textField.String(data)
		require.NoError(t, err)
		advices = append(advices, text)
		return nil
	}
	gadgetRunner.RunGadget()

	require.Len(t, advices, 1, "expected exactly one advice packet (one container observed)")
	advice := advices[0]

	require.True(t, strings.HasPrefix(advice, "# "+containerName+"\n"),
		"advice should carry the container-name comment header:\n%s", advice)
	require.Contains(t, advice, "securityContext:\n  readOnlyRootFilesystem: true\n",
		"advice must always recommend a read-only rootfs baseline")
	require.Contains(t, advice, "  - "+writeDir+"\n",
		"the written directory must be carved out as writable")
	require.NotContains(t, advice, readDir,
		"a directory that was only read from must not be writable")
}

// containerNameEnricher mirrors the in-tree advise_seccomp unit test: the
// gadget resolves container names from the runtime.containerName /
// k8s.containerName fields, which in a real run IG's container manager
// attaches. There is no container manager in the harness, so a simple operator
// stamps the name onto rows whose mntns id matches the runner's.
func containerNameEnricher(t *testing.T, dsName string, runner *utilstest.Runner) operators.DataOperator {
	return simple.New("enrich-container-name",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			ds := gadgetCtx.GetDataSources()[dsName]
			require.NotNil(t, ds)

			runtimeNameF, err := ds.AddField("runtime.containerName", api.Kind_String)
			require.NoError(t, err)
			k8sNameF, err := ds.AddField("k8s.containerName", api.Kind_String)
			require.NoError(t, err)

			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				mntnsidF := ds.GetField("mntns_id_raw")
				require.NotNil(t, mntnsidF)
				mntnsid, err := mntnsidF.Uint64(data)
				require.NoError(t, err)
				if mntnsid != runner.Info.MountNsID {
					return nil
				}
				require.NoError(t, runtimeNameF.PutString(data, containerName))
				require.NoError(t, k8sNameF.PutString(data, containerName))
				return nil
			}, 100)
			return nil
		}),
	)
}
