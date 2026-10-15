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
	"sync"
	"testing"
	"time"
)

func TestECHRecordPublicationUpdatesLiveConfig(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"public.example": {
				{ConfigID: 7, RawPublicName: "public.example"}, // no publication history yet
				{ConfigID: 9, RawPublicName: "public.example"},
			},
		},
	}
	pubTime := time.Now()

	metaBytes, ok, err := ech.recordPublication(7, "dns/example", []string{"a.example", "b.example"}, pubTime)
	if err != nil || !ok || len(metaBytes) == 0 {
		t.Fatalf("recordPublication() = (%q, %v, %v), want metadata and ok", metaBytes, ok, err)
	}

	// the state must be recorded on the config the server holds, not a copy,
	// or the next publication pass would publish everything again
	live := ech.configs["public.example"][0]
	for _, name := range []string{"a.example", "b.example"} {
		if _, published := live.meta.Publications["dns/example"][name]; !published {
			t.Errorf("expected live config to record publication for %s", name)
		}
	}
	if other := ech.configs["public.example"][1]; len(other.meta.Publications) != 0 {
		t.Errorf("publication recorded on the wrong config: %v", other.meta.Publications)
	}

	// a later pass for another name adds to the existing history
	if _, ok, err := ech.recordPublication(7, "dns/example", []string{"c.example"}, pubTime); err != nil || !ok {
		t.Fatalf("recordPublication() ok=%v err=%v", ok, err)
	}
	if got := len(ech.configs["public.example"][0].meta.Publications["dns/example"]); got != 3 {
		t.Errorf("expected 3 published names, got %d", got)
	}

	// a config that was rotated out is skipped rather than resurrected
	if _, ok, err := ech.recordPublication(200, "dns/example", []string{"a.example"}, pubTime); err != nil || ok {
		t.Errorf("expected ok=false for unknown config, got ok=%v err=%v", ok, err)
	}
}

func TestECHConfigsToPublishMatchesNamesCaseInsensitively(t *testing.T) {
	ech := &ECH{
		configsMu: new(sync.RWMutex),
		configs: map[string][]echConfig{
			"public.example": {{ConfigID: 1}},
			"other.example":  {{ConfigID: 2}, {ConfigID: 3}},
		},
	}

	for i, tc := range []struct {
		names   []string
		wantIDs int
	}{
		{names: nil, wantIDs: 3},
		{names: []string{"public.example"}, wantIDs: 1},
		{names: []string{"Public.Example"}, wantIDs: 1},
		{names: []string{" PUBLIC.example "}, wantIDs: 1},
		{names: []string{"public.example", "OTHER.example"}, wantIDs: 3},
		{names: []string{"missing.example"}, wantIDs: 0},
		{names: []string{}, wantIDs: 0},
	} {
		list, ids := ech.configsToPublish(tc.names)
		if len(ids) != tc.wantIDs || len(list) != tc.wantIDs {
			t.Errorf("Test %d: names %q: got %d configs / %d IDs, want %d", i, tc.names, len(list), len(ids), tc.wantIDs)
		}
	}
}
