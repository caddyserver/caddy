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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestTLSStorageCleanStopSynchronization(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tlsApp := &TLS{
		ctx:    ctx,
		logger: zap.NewNop(),
		Automation: &AutomationConfig{
			StorageCleanInterval: caddy.Duration(1 * time.Hour),
		},
	}

	// Start storage cleaner
	tlsApp.keepStorageClean()

	// Stop must cancel cleaner context and wait for completion cleanly
	err := tlsApp.Stop()
	if err != nil {
		t.Fatalf("TLS.Stop failed: %v", err)
	}
}

func TestTLSStorageCleanUnitsCanceledContext(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	cancel() // canceled immediately

	tlsApp := &TLS{
		ctx:    ctx,
		logger: zap.NewNop(),
	}

	// cleanStorageUnits with canceled context should return immediately
	tlsApp.cleanStorageUnits(ctx.Context)
}
