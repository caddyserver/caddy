// Copyright 2015 Light Code Labs, LLC
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

package caddytls

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"sync"
	"time"
)

// RotateSessionTicketKeys rotates the TLS session ticket keys
// on cfg every TicketRotateInterval. It spawns a new goroutine so
// this function does NOT block. It returns a channel you should
// close when you are ready to stop the key rotation, like when the
// server using cfg is no longer running.
//
// TODO: See about moving this into CertMagic and using its Storage
func RotateSessionTicketKeys(cfg *tls.Config) chan struct{} {
	ch := make(chan struct{})
	ticker := time.NewTicker(TicketRotateInterval)
	go runTLSTicketKeyRotation(cfg, ticker, ch)
	return ch
}

// Functions that may be swapped out for testing
var (
	runTLSTicketKeyRotation        = standaloneTLSTicketKeyRotation
	setSessionTicketKeysTestHook   = func(keys [][32]byte) [][32]byte { return keys }
	setSessionTicketKeysTestHookMu sync.Mutex
)

// standaloneTLSTicketKeyRotation governs over the array of TLS ticket keys used to de/crypt TLS tickets.
// It periodically sets a new ticket key as the first one, used to encrypt (and decrypt),
// pushing any old ticket keys to the back, where they are considered for decryption only.
//
// Lack of entropy for the very first ticket key results in the feature being disabled (as does Go),
// later lack of entropy temporarily disables ticket key rotation.
// Old ticket keys are still phased out, though.
//
// Stops the ticker when returning.
func standaloneTLSTicketKeyRotation(c *tls.Config, ticker *time.Ticker, exitChan chan struct{}) {
	defer ticker.Stop()

	// The entire page should be marked as sticky, but Go cannot do that
	// without resorting to syscall#Mlock. And, we don't have madvise (for NODUMP), too. ☹
	keys := make([][32]byte, 1, NumTickets)

	rng := c.Rand
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, keys[0][:]); err != nil {
		c.SessionTicketsDisabled = true // bail if we don't have the entropy for the first one
		return
	}
	setSessionTicketKeysTestHookMu.Lock()
	setSessionTicketKeysHook := setSessionTicketKeysTestHook
	setSessionTicketKeysTestHookMu.Unlock()
	c.SetSessionTicketKeys(setSessionTicketKeysHook(keys))

	for {
		select {
		case _, isOpen := <-exitChan:
			if !isOpen {
				return
			}
		case <-ticker.C:
			rng = c.Rand // could've changed since the start
			if rng == nil {
				rng = rand.Reader
			}
			var newTicketKey [32]byte
			_, err := io.ReadFull(rng, newTicketKey[:])

			if len(keys) < NumTickets {
				keys = append(keys, keys[0]) // manipulates the internal length
			}
			for idx := len(keys) - 1; idx >= 1; idx-- {
				keys[idx] = keys[idx-1] // yes, this makes copies
			}

			if err == nil {
				keys[0] = newTicketKey
			}
			// pushes the last key out, doesn't matter that we don't have a new one
			c.SetSessionTicketKeys(setSessionTicketKeysHook(keys))
		}
	}
}

const (
	// NumTickets is how many tickets to hold and consider
	// to decrypt TLS sessions.
	NumTickets = 4

	// TicketRotateInterval is how often to generate
	// new ticket for TLS PFS encryption
	TicketRotateInterval = 10 * time.Hour
)
