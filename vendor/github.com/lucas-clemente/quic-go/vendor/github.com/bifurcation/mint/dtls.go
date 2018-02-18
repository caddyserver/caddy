package mint

import (
	"fmt"
)

// This file is a placeholder. DTLS-specific stuff (timer management,
// ACKs, retransmits, etc. will eventually go here.
const (
	initialMtu = 1200
)

func wireVersion(h *HandshakeLayer) uint16 {
	if h.datagram {
		return dtls12WireVersion
	}
	return tls12Version
}

func dtlsConvertVersion(version uint16) uint16 {
	if version == tls12Version {
		return dtls12WireVersion
	}
	if version == tls10Version {
		return 0xfeff
	}
	panic(fmt.Sprintf("Internal error, unexpected version=%d", version))
}
