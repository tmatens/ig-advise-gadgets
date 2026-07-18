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

// WASM operator for the advise_devices gadget. The eBPF map iterator emits one
// row per (container, /dev path); this operator groups by container and renders
// a minimal devices: grant (default nodes filtered out), one packet per
// container. The default-device filtering is pure logic in the advice package.
package main

import (
	"slices"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

	"github.com/tmatens/ig-advise-gadgets/advise_devices/go/advice"
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
	devices   []string
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	devicesDS, err := api.GetDataSource("devices")
	if err != nil {
		api.Errorf("getting devices datasource: %s", err)
		return 1
	}
	pathF, err := devicesDS.GetField("path")
	if err != nil {
		api.Errorf("getting path field: %s", err)
		return 1
	}
	mntnsF, err := devicesDS.GetField("mntns_id_raw")
	if err != nil {
		api.Errorf("getting mntns_id_raw field: %s", err)
		return 1
	}
	k8sContainerF, err := devicesDS.GetField("k8s.containerName")
	if err != nil {
		api.Errorf("getting k8s.containerName field: %s", err)
		return 1
	}
	runtimeContainerF, err := devicesDS.GetField("runtime.containerName")
	if err != nil {
		api.Errorf("getting runtime.containerName field: %s", err)
		return 1
	}

	err = devicesDS.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		dropped := droppedObservations()
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
			g.devices = append(g.devices, p)
		}

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
			adviseField.SetString(api.Data(nd),
				advice.Render(g.container, g.devices)+advice.OverflowWarning(dropped))
			adviseDS.EmitAndRelease(api.Packet(nd))
		}
		return nil
	}, 9999)
	if err != nil {
		api.Warnf("subscribing to devices: %s", err)
		return 1
	}
	return 0
}

// droppedObservations reads the eBPF-side drop counter. Non-zero means a map
// filled up during the run and the recommendation is missing observations; the
// count is warned once and stamped into every advice packet as a YAML comment.
func droppedObservations() uint64 {
	dropsMap, err := api.GetMap("drops")
	if err != nil {
		api.Warnf("getting drops map: %s", err)
		return 0
	}
	var dropped uint64
	if err := dropsMap.Lookup(uint32(0), &dropped); err != nil {
		return 0
	}
	if dropped > 0 {
		api.Warnf("%d observation(s) dropped (eBPF map full); recommendations may be incomplete", dropped)
	}
	return dropped
}

func main() {}
