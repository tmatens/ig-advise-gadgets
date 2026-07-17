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

// WASM operator for the advise_filesystem gadget. The eBPF map iterator emits
// one row per (container, write-intent path); this operator groups the paths by
// container and renders a read_only + tmpfs recommendation, one packet per
// container.
//
// The mechanical aggregation lives here; the opinionated half (volume vs tmpfs
// correlation, confidence, multi-format output) belongs in downstream tooling
// (e.g. a Compose/Kubernetes policy generator), not here. See ../README.md.
package main

import (
	"slices"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

	"github.com/tmatens/ig-advise-gadgets/advise_filesystem/go/advice"
)

var (
	adviseDS    api.DataSource
	adviseField api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	adviseDS, err = api.NewDataSource("advise", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %s", err)
		return 1
	}
	adviseField, err = adviseDS.AddField("text", api.Kind_String)
	if err != nil {
		api.Errorf("adding field: %s", err)
		return 1
	}
	return 0
}

type group struct {
	container string
	paths     []string
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	filesDS, err := api.GetDataSource("files")
	if err != nil {
		api.Errorf("getting files datasource: %s", err)
		return 1
	}
	pathF, err := filesDS.GetField("path")
	if err != nil {
		api.Errorf("getting path field: %s", err)
		return 1
	}
	mntnsF, err := filesDS.GetField("mntns_id_raw")
	if err != nil {
		api.Errorf("getting mntns_id_raw field: %s", err)
		return 1
	}
	k8sContainerF, err := filesDS.GetField("k8s.containerName")
	if err != nil {
		api.Errorf("getting k8s.containerName field: %s", err)
		return 1
	}
	runtimeContainerF, err := filesDS.GetField("runtime.containerName")
	if err != nil {
		api.Errorf("getting runtime.containerName field: %s", err)
		return 1
	}

	err = filesDS.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		// The map iterator delivers the whole map at flush/stop; group the
		// per-path rows by container before rendering one advice per container.
		groups := map[uint64]*group{}
		for j := 0; j < dataArr.Len(); j++ {
			data := dataArr.Get(j)

			mntnsid, err := mntnsF.Uint64(data)
			if err != nil {
				api.Warnf("reading mntns id: %s", err)
				continue
			}
			if api.ShouldDiscardMntNsID(mntnsid) {
				continue
			}
			p, err := pathF.String(data, 512)
			if err != nil {
				api.Warnf("reading path: %s", err)
				continue
			}
			if p == "" {
				continue
			}

			g := groups[mntnsid]
			if g == nil {
				k8sName, _ := k8sContainerF.String(data, 512)
				runtimeName, _ := runtimeContainerF.String(data, 512)
				name := k8sName
				if name == "" {
					name = runtimeName
				}
				g = &group{container: name}
				groups[mntnsid] = g
			}
			g.paths = append(g.paths, p)
		}

		// Emit in a deterministic order (by mntns id) so output is stable.
		ids := make([]uint64, 0, len(groups))
		for id := range groups {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			g := groups[id]
			nd, err := adviseDS.NewPacketSingle()
			if err != nil {
				api.Warnf("creating packet: %s", err)
				continue
			}
			adviseField.SetString(api.Data(nd), advice.Render(g.container, g.paths))
			adviseDS.EmitAndRelease(api.Packet(nd))
		}
		return nil
	}, 9999)
	if err != nil {
		api.Warnf("subscribing to files: %s", err)
		return 1
	}
	return 0
}

func main() {}
