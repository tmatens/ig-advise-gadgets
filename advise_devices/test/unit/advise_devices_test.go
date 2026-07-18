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

// Package tests drives the real advise_devices gadget end-to-end through
// Inspektor Gadget's gadgetrunner harness (the same pattern as the in-tree
// advise_seccomp unit test): the built gadget image runs in-process, a runner
// thread in its own mount namespace opens a default device node (/dev/null)
// and a non-default one (/dev/fuse), and the emitted advise packet is asserted
// to grant only the non-default node.
//
// Requires root (eBPF) and the gadget image in the local OCI store; see dev.md
// for the build + invocation (go test -exec 'sudo -E' with GADGET_TAG set).
package tests

import (
	"os"
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

const (
	containerName    = "test-advise-devices"
	nonDefaultDevice = "/dev/fuse"
)

func TestAdviseDevicesGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	if _, err := os.Stat(nonDefaultDevice); err != nil {
		t.Skipf("test requires %s on the host: %s", nonDefaultDevice, err)
	}

	runner := utilstest.NewRunnerWithTest(t, &utilstest.RunnerConfig{})
	mntnsFilterMap := utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID)

	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utilstest.RunWithRunner(t, runner, func() error {
			// A default node: opened, but must be filtered out of the grant.
			if f, err := os.Open("/dev/null"); err != nil {
				return err
			} else {
				f.Close()
			}
			// The non-default node the grant must list.
			f, err := os.OpenFile(nonDefaultDevice, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			return f.Close()
		})
		return nil
	}
	opts := gadgetrunner.GadgetRunnerOpts[any]{
		Image:          "advise_devices",
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
		containerNameEnricher(t, "devices", runner))
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
	require.Contains(t, advice, "device_nodes:\n",
		"a non-default device open must yield a device_nodes grant")
	require.Contains(t, advice, "  - "+nonDefaultDevice+"\n",
		"the non-default node must be granted")
	require.NotContains(t, advice, "/dev/null",
		"default device nodes must be filtered out of the grant")
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
