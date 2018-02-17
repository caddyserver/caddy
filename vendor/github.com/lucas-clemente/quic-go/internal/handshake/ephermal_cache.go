package handshake

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
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
func getEphermalKEX() (res crypto.KeyExchange) {
	kexMutex.RLock()
	res = kexCurrent
	t := kexCurrentTime
	kexMutex.RUnlock()
	if res != nil && time.Since(t) < kexLifetime {
		return res
	}

	kexMutex.Lock()
	defer kexMutex.Unlock()
	// Check if still unfulfilled
	if kexCurrent == nil || time.Since(kexCurrentTime) > kexLifetime {
		kex, err := crypto.NewCurve25519KEX()
		if err != nil {
			utils.Errorf("could not set KEX: %s", err.Error())
			return kexCurrent
		}
		kexCurrent = kex
		kexCurrentTime = time.Now()
		return kexCurrent
	}
	return kexCurrent
}
