// Copyright 2015 Matthew Holt and The Caddy Authors
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

package standardstek

import (
	"log"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(standardSTEKProvider{})
}

type standardSTEKProvider struct {
	stekConfig *caddytls.SessionTicketService
	timer      *time.Timer
}

// CaddyModule returns the Caddy module information.
func (standardSTEKProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.stek.standard",
		New: func() caddy.Module { return new(standardSTEKProvider) },
	}
}

// Initialize sets the configuration for s and returns the starting keys.
func (s *standardSTEKProvider) Initialize(config *caddytls.SessionTicketService) ([][32]byte, error) {
	// keep a reference to the config; we'll need it when rotating keys
	s.stekConfig = config

	itvl := time.Duration(s.stekConfig.RotationInterval)

	mutex.Lock()
	defer mutex.Unlock()

	// if this is our first rotation or we are overdue
	// for one, perform a rotation immediately; otherwise,
	// we assume that the keys are non-empty and fresh
	since := time.Since(lastRotation)
	if lastRotation.IsZero() || since > itvl {
		var err error
		keys, err = s.stekConfig.RotateSTEKs(keys)
		if err != nil {
			return nil, err
		}
		since = 0 // since this is overdue or is the first rotation, use full interval
		lastRotation = time.Now()
	}

	// create timer for the remaining time on the interval;
	// this timer is cleaned up only when Next() returns
	s.timer = time.NewTimer(itvl - since)

	return keys, nil
}

// Next returns a channel which transmits the latest session ticket keys.
func (s *standardSTEKProvider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	keysChan := make(chan [][32]byte)
	go s.rotate(doneChan, keysChan)
	return keysChan
}

// rotate rotates keys on a regular basis, sending each updated set of
// keys down keysChan, until doneChan is closed.
func (s *standardSTEKProvider) rotate(doneChan <-chan struct{}, keysChan chan<- [][32]byte) {
	for {
		select {
		case now := <-s.timer.C:
			// copy the slice header to avoid races
			mutex.RLock()
			keysCopy := keys
			mutex.RUnlock()

			// generate a new key, rotating old ones
			var err error
			keysCopy, err = s.stekConfig.RotateSTEKs(keysCopy)
			if err != nil {
				// TODO: improve this handling
				log.Printf("[ERROR] Generating STEK: %v", err)
				continue
			}

			// replace keys slice with updated value and
			// record the timestamp of rotation
			mutex.Lock()
			keys = keysCopy
			lastRotation = now
			mutex.Unlock()

			// send the updated keys to the service
			keysChan <- keysCopy

			// timer channel is already drained, so reset directly (see godoc)
			s.timer.Reset(time.Duration(s.stekConfig.RotationInterval))

		case <-doneChan:
			// again, see godocs for why timer is stopped this way
			if !s.timer.Stop() {
				<-s.timer.C
			}
			return
		}
	}
}

var (
	lastRotation time.Time
	keys         [][32]byte
	mutex        sync.RWMutex // protects keys and lastRotation
)

// Interface guard
var _ caddytls.STEKProvider = (*standardSTEKProvider)(nil)
