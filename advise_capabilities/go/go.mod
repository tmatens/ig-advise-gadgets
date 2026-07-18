module github.com/tmatens/ig-advise-gadgets/advise_capabilities/go

go 1.25.7

// Out-of-tree build (this repo): pin the Inspektor Gadget module that provides
// wasmapi/go. Keep in lockstep with the repo-root IG_VERSION file.
require github.com/inspektor-gadget/inspektor-gadget v0.54.0

// If/when this gadget is upstreamed into the inspektor-gadget tree,
// the other gadgets use `module main` with an in-tree replace directive:
//   module main
//   require github.com/inspektor-gadget/inspektor-gadget v0.0.0
//   replace github.com/inspektor-gadget/inspektor-gadget => ../../../
// (and the advice subpackage import path becomes main/advice).
