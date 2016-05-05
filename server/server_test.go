package server

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestStandaloneTLSTicketKeyRotation(t *testing.T) {
	tlsGovChan := make(chan struct{})
	defer close(tlsGovChan)
	callSync := make(chan bool, 1)
	defer close(callSync)

	oldHook := setSessionTicketKeysTestHook
	defer func() {
		setSessionTicketKeysTestHook = oldHook
	}()
	var keysInUse [][32]byte
	setSessionTicketKeysTestHook = func(keys [][32]byte) [][32]byte {
		keysInUse = keys
		callSync <- true
		return keys
	}

	c := new(tls.Config)
	timer := time.NewTicker(time.Millisecond * 1)

	go standaloneTLSTicketKeyRotation(c, timer, tlsGovChan)

	rounds := 0
	var lastTicketKey [32]byte
	for {
		select {
		case <-callSync:
			if lastTicketKey == keysInUse[0] {
				close(tlsGovChan)
				t.Errorf("The same TLS ticket key has been used again (not rotated): %x.", lastTicketKey)
				return
			}
			lastTicketKey = keysInUse[0]
			rounds++
			if rounds <= tlsNumTickets && len(keysInUse) != rounds {
				close(tlsGovChan)
				t.Errorf("Expected TLS ticket keys in use: %d; Got instead: %d.", rounds, len(keysInUse))
				return
			}
			if c.SessionTicketsDisabled == true {
				t.Error("Session tickets have been disabled unexpectedly.")
				return
			}
			if rounds >= tlsNumTickets+1 {
				return
			}
		case <-time.After(time.Second * 1):
			t.Errorf("Timeout after %d rounds.", rounds)
			return
		}
	}
}
