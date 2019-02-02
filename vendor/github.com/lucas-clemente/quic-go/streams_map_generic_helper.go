package quic

import "github.com/cheekybits/genny/generic"

// In the auto-generated streams maps, we need to be able to close the streams.
// Therefore, extend the generic.Type with the stream close method.
// This definition must be in a file that Genny doesn't process.
type item interface {
	generic.Type
	closeForShutdown(error)
}
