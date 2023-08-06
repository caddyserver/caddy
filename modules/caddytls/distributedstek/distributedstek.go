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

// Package distributedstek provides TLS session ticket ephemeral
// keys (STEKs) in a distributed fashion by utilizing configured
// storage for locking and key sharing. This allows a cluster of
// machines to optimally resume TLS sessions in a load-balanced
// environment without any hassle. This is similar to what
// Twitter does, but without needing to rely on SSH, as it is
// built into the web server this way:
// https://blog.twitter.com/engineering/en_us/a/2013/forward-secrecy-at-twitter.html
package distributedstek

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"runtime/debug"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements a distributed STEK provider. This
// module will obtain STEKs from a storage module instead
// of generating STEKs internally. This allows STEKs to be
// coordinated, improving TLS session resumption in a cluster.
type Provider struct {
	// The storage module wherein to store and obtain session
	// ticket keys. If unset, Caddy's default/global-configured
	// storage module will be used.
	Storage json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	storage    certmagic.Storage
	stekConfig *caddytls.SessionTicketService
	timer      *time.Timer
	ctx        caddy.Context
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.stek.distributed",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision provisions s.
func (s *Provider) Provision(ctx caddy.Context) error {
	s.ctx = ctx

	// unpack the storage module to use, if different from the default
	if s.Storage != nil {
		val, err := ctx.LoadModule(s, "Storage")
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %s", err)
		}
		cmStorage, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating TLS storage configuration: %v", err)
		}
		s.storage = cmStorage
	}

	// otherwise, use default storage
	if s.storage == nil {
		s.storage = ctx.Storage()
	}

	return nil
}

// Initialize sets the configuration for s and returns the starting keys.
func (s *Provider) Initialize(config *caddytls.SessionTicketService) ([][32]byte, error) {
	// keep a reference to the config; we'll need it when rotating keys
	s.stekConfig = config

	dstek, err := s.getSTEK()
	if err != nil {
		return nil, err
	}

	// create timer for the remaining time on the interval;
	// this timer is cleaned up only when rotate() returns
	s.timer = time.NewTimer(time.Until(dstek.NextRotation))

	return dstek.Keys, nil
}

// Next returns a channel which transmits the latest session ticket keys.
func (s *Provider) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	keysChan := make(chan [][32]byte)
	go s.rotate(doneChan, keysChan)
	return keysChan
}

func (s *Provider) loadSTEK() (distributedSTEK, error) {
	var sg distributedSTEK
	gobBytes, err := s.storage.Load(s.ctx, stekFileName)
	if err != nil {
		return sg, err // don't wrap, in case error is certmagic.ErrNotExist
	}
	dec := gob.NewDecoder(bytes.NewReader(gobBytes))
	err = dec.Decode(&sg)
	if err != nil {
		return sg, fmt.Errorf("STEK gob corrupted: %v", err)
	}
	return sg, nil
}

func (s *Provider) storeSTEK(dstek distributedSTEK) error {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(dstek)
	if err != nil {
		return fmt.Errorf("encoding STEK gob: %v", err)
	}
	err = s.storage.Store(s.ctx, stekFileName, buf.Bytes())
	if err != nil {
		return fmt.Errorf("storing STEK gob: %v", err)
	}
	return nil
}

// getSTEK locks and loads the current STEK from storage. If none
// currently exists, a new STEK is created and persisted. If the
// current STEK is outdated (NextRotation time is in the past),
// then it is rotated and persisted. The resulting STEK is returned.
func (s *Provider) getSTEK() (distributedSTEK, error) {
	err := s.storage.Lock(s.ctx, stekLockName)
	if err != nil {
		return distributedSTEK{}, fmt.Errorf("failed to acquire storage lock: %v", err)
	}

	//nolint:errcheck
	defer s.storage.Unlock(s.ctx, stekLockName)

	// load the current STEKs from storage
	dstek, err := s.loadSTEK()
	if errors.Is(err, fs.ErrNotExist) {
		// if there is none, then make some right away
		dstek, err = s.rotateKeys(dstek)
		if err != nil {
			return dstek, fmt.Errorf("creating new STEK: %v", err)
		}
	} else if err != nil {
		// some other error, that's a problem
		return dstek, fmt.Errorf("loading STEK: %v", err)
	} else if time.Now().After(dstek.NextRotation) {
		// if current STEKs are outdated, rotate them
		dstek, err = s.rotateKeys(dstek)
		if err != nil {
			return dstek, fmt.Errorf("rotating keys: %v", err)
		}
	}

	return dstek, nil
}

// rotateKeys rotates the keys of oldSTEK and returns the new distributedSTEK
// with updated keys and timestamps. It stores the returned STEK in storage,
// so this function must only be called in a storage-provided lock.
func (s *Provider) rotateKeys(oldSTEK distributedSTEK) (distributedSTEK, error) {
	var newSTEK distributedSTEK
	var err error

	newSTEK.Keys, err = s.stekConfig.RotateSTEKs(oldSTEK.Keys)
	if err != nil {
		return newSTEK, err
	}

	now := time.Now()
	newSTEK.LastRotation = now
	newSTEK.NextRotation = now.Add(time.Duration(s.stekConfig.RotationInterval))

	err = s.storeSTEK(newSTEK)
	if err != nil {
		return newSTEK, err
	}

	return newSTEK, nil
}

// rotate rotates keys on a regular basis, sending each updated set of
// keys down keysChan, until doneChan is closed.
func (s *Provider) rotate(doneChan <-chan struct{}, keysChan chan<- [][32]byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] distributed STEK rotation: %v\n%s", err, debug.Stack())
		}
	}()
	for {
		select {
		case <-s.timer.C:
			dstek, err := s.getSTEK()
			if err != nil {
				// TODO: improve this handling
				log.Printf("[ERROR] Loading STEK: %v", err)
				continue
			}

			// send the updated keys to the service
			keysChan <- dstek.Keys

			// timer channel is already drained, so reset directly (see godoc)
			s.timer.Reset(time.Until(dstek.NextRotation))

		case <-doneChan:
			// again, see godocs for why timer is stopped this way
			if !s.timer.Stop() {
				<-s.timer.C
			}
			return
		}
	}
}

type distributedSTEK struct {
	Keys                       [][32]byte
	LastRotation, NextRotation time.Time
}

const (
	stekLockName = "stek_check"
	stekFileName = "stek/stek.bin"
)

// Interface guard
var _ caddytls.STEKProvider = (*Provider)(nil)
