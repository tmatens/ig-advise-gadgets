module github.com/tmatens/ig-advise-gadgets/advise_devices/go

go 1.25.7

// Out-of-tree build: pin the Inspektor Gadget module providing wasmapi/go.
// Keep in lockstep with the repo-root IG_VERSION file.
require github.com/inspektor-gadget/inspektor-gadget v0.54.0
