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

// WASM operator for the advise_capabilities gadget. It reads the per-container
// held-capability bitmap emitted by the eBPF map iterator and turns it into a
// compose-style cap_drop/cap_add recommendation, one packet per container.
//
// This is the MECHANICAL half of the advisor (per-container union of held
// capabilities). The opinionated half — init-window / runc-noise suppression,
// the confidence rubric, entrypoint cross-check, and multi-format output — lives
// in downstream tooling by design, not here. See ../README.md.
package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

	"github.com/tmatens/ig-advise-gadgets/advise_capabilities/go/advice"
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

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	capsDS, err := api.GetDataSource("capabilities")
	if err != nil {
		api.Errorf("getting capabilities datasource: %s", err)
		return 1
	}

	capsF, err := capsDS.GetField("caps")
	if err != nil {
		api.Errorf("getting caps field: %s", err)
		return 1
	}
	mntnsF, err := capsDS.GetField("mntns_id_raw")
	if err != nil {
		api.Errorf("getting mntns_id_raw field: %s", err)
		return 1
	}
	k8sContainerF, err := capsDS.GetField("k8s.containerName")
	if err != nil {
		api.Errorf("getting k8s.containerName field: %s", err)
		return 1
	}
	runtimeContainerF, err := capsDS.GetField("runtime.containerName")
	if err != nil {
		api.Errorf("getting runtime.containerName field: %s", err)
		return 1
	}

	err = capsDS.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		dropped := droppedObservations()
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

			bitmap, err := capsF.Uint64(data)
			if err != nil {
				api.Warnf("reading caps bitmap: %s", err)
				continue
			}

			k8sName, _ := k8sContainerF.String(data, 512)
			runtimeName, _ := runtimeContainerF.String(data, 512)
			containerName := k8sName
			if containerName == "" {
				containerName = runtimeName
			}

			nd, err := adviseDS.NewPacketSingle()
			if err != nil {
				api.Warnf("creating packet: %s", err)
				continue
			}
			adviseField.SetString(api.Data(nd),
				advice.Render(containerName, bitmap)+advice.OverflowWarning(dropped))
			adviseDS.EmitAndRelease(api.Packet(nd))
		}
		return nil
	}, 9999)
	if err != nil {
		api.Warnf("subscribing to capabilities: %s", err)
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
