package handshake

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var (
	kexLifetime    = protocol.EphermalKeyLifetime
	kexCurrent     crypto.KeyExchange
	kexCurrentTime time.Time
	kexMutex       sync.RWMutex
)

// getEphermalKEX returns the currently active KEX, which changes every protocol.EphermalKeyLifetime
// See the explanation from the QUIC crypto doc:
//
// A single connection is the usual scope for forward security, but the security
// difference between an ephemeral key used for a single connection, and one
// used for all connections for 60 seconds is negligible. Thus we can amortise
// the Diffie-Hellman key generation at the server over all the connections in a
// small time span.
func getEphermalKEX() (crypto.KeyExchange, error) {
	kexMutex.RLock()
	res := kexCurrent
	t := kexCurrentTime
	kexMutex.RUnlock()
	if res != nil && time.Since(t) < kexLifetime {
		return res, nil
	}

	kexMutex.Lock()
	defer kexMutex.Unlock()
	// Check if still unfulfilled
	if kexCurrent == nil || time.Since(kexCurrentTime) >= kexLifetime {
		kex, err := crypto.NewCurve25519KEX()
		if err != nil {
			return nil, err
		}
		kexCurrent = kex
		kexCurrentTime = time.Now()
		return kexCurrent, nil
	}
	return kexCurrent, nil
}
