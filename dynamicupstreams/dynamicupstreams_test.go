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

package dynamicupstreams

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestSRVResolvesAndCaches(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{
			{Target: "a.example.", Port: 5432, Priority: 1, Weight: 10},
			{Target: "b.example.", Port: 5433, Priority: 1, Weight: 20},
		}, nil
	}

	targets, err := SRV(context.Background(), lookup, "svc-cache", "tcp", "x", time.Minute, 0, zap.NewNop())
	if err != nil {
		t.Fatalf("SRV: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Host != "a.example." || targets[0].Port != "5432" || targets[0].Weight != 10 {
		t.Errorf("unexpected first target: %+v", targets[0])
	}

	// second call within refresh must be served from cache (no extra lookup)
	if _, err := SRV(context.Background(), lookup, "svc-cache", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatalf("SRV (cached): %v", err)
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1 (cached)", calls)
	}
}

func TestSRVErrorWithoutGrace(t *testing.T) {
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	}
	if _, err := SRV(context.Background(), lookup, "svc-err", "tcp", "x", time.Minute, 0, zap.NewNop()); err == nil {
		t.Fatal("expected an error when lookup fails and nothing is cached")
	}
}

func TestSRVGracePeriodServesStale(t *testing.T) {
	ok := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	// tiny refresh so the entry is immediately stale on the next call
	if _, err := SRV(context.Background(), ok, "svc-grace", "tcp", "x", time.Nanosecond, time.Hour, zap.NewNop()); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	fail := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	}
	targets, err := SRV(context.Background(), fail, "svc-grace", "tcp", "x", time.Nanosecond, time.Hour, zap.NewNop())
	if err != nil {
		t.Fatalf("grace period should suppress the error: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("expected the stale cached target to be served, got %d", len(targets))
	}
}

func TestResetSRV(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	if _, err := SRV(context.Background(), lookup, "svc-reset", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	ResetSRV("svc-reset", "tcp", "x")
	if _, err := SRV(context.Background(), lookup, "svc-reset", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("lookup calls = %d, want 2 (cache was reset between calls)", calls)
	}
}

func TestAResolvesAndCaches(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}, nil
	}

	targets, err := A(context.Background(), lookup, "ip", "db.a-test", "5432", time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Host != "10.0.0.1" || targets[0].Port != "5432" {
		t.Errorf("unexpected first target: %+v", targets[0])
	}

	if _, err := A(context.Background(), lookup, "ip", "db.a-test", "5432", time.Minute, zap.NewNop()); err != nil {
		t.Fatalf("A (cached): %v", err)
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1 (cached)", calls)
	}
}

func TestAError(t *testing.T) {
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("dns boom")
	}
	if _, err := A(context.Background(), lookup, "ip", "db.a-err", "5432", time.Minute, zap.NewNop()); err == nil {
		t.Fatal("expected an error when the A lookup fails")
	}
}
