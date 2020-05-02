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

package caddytls

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/libdns/libdns"
)

// TODO: this is borrowed from https://github.com/mholt/acme - once we
// switch to that acme library, this file will go away

// solver is a type that makes libdns providers usable as ACME challenge solvers.
type solver struct {
	recordManager

	TTL time.Duration

	txtRecords   map[string]libdns.Record // keyed by challenge token
	txtRecordsMu sync.Mutex
}

func (s *solver) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	rec := libdns.Record{
		Type:  "TXT",
		Name:  fqdn,
		Value: value,
		TTL:   s.TTL,
	}

	zone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return fmt.Errorf("could not determine zone for domain %q: %v", fqdn, err)
	}

	results, err := s.recordManager.AppendRecords(context.TODO(), zone, []libdns.Record{rec})
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return fmt.Errorf("expected one record, got %d: %v", len(results), results)
	}

	// keep this record handy so we can clean it up more efficiently
	s.txtRecordsMu.Lock()
	if s.txtRecords == nil {
		s.txtRecords = make(map[string]libdns.Record)
	}
	s.txtRecords[keyAuth] = results[0]
	s.txtRecordsMu.Unlock()

	// TODO: check for record propagation before continuing (accordig to config)

	return nil
}

func (s *solver) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	// retrieve the record we created
	s.txtRecordsMu.Lock()
	txtRec, ok := s.txtRecords[keyAuth]
	if !ok {
		s.txtRecordsMu.Unlock()
		return fmt.Errorf("no memory of presenting a DNS record for %v", domain)
	}
	s.txtRecordsMu.Unlock()

	// clean up the record
	_, err = s.recordManager.DeleteRecords(context.TODO(), authZone, []libdns.Record{txtRec})
	if err != nil {
		return err
	}

	// once it has been successfully cleaned up, we can forget about it
	s.txtRecordsMu.Lock()
	delete(s.txtRecords, keyAuth)
	s.txtRecordsMu.Unlock()

	return nil
}

// recordManager defines the set of operations required for ACME challenges.
type recordManager interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

var _ challenge.Provider = (*solver)(nil)
