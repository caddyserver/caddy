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

//go:build !unix || solaris

package caddy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestFakeCloseListenerSiblingSurvivesClose pins that closing one fakeCloseListener
// does not wedge another sharing the same socket, as happens during a config reload.
func TestFakeCloseListenerSiblingSurvivesClose(t *testing.T) {
	const network, address = "tcp", "127.0.0.1:0"
	lnKey := "test|" + network + "/" + address

	ctx := context.Background()

	first, err := listenReusable(ctx, lnKey, network, address, net.ListenConfig{})
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	oldServer := first.(*fakeCloseListener)

	second, err := listenReusable(ctx, lnKey, network, address, net.ListenConfig{})
	if err != nil {
		t.Fatalf("second listen: %v", err)
	}
	newServer := second.(*fakeCloseListener)
	defer newServer.Close()

	if err := oldServer.Close(); err != nil {
		t.Fatalf("close old server: %v", err)
	}

	addr := newServer.Addr().String()

	// Emulate the net/http accept loop, which retries timeouts as temporary.
	accepted := make(chan net.Conn, 1)
	fatal := make(chan error, 1)
	go func() {
		for {
			conn, err := newServer.Accept()
			if err == nil {
				accepted <- conn
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			fatal <- err
			return
		}
	}()

	dialed, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial surviving listener: %v", err)
	}
	defer dialed.Close()

	select {
	case conn := <-accepted:
		conn.Close()
	case err := <-fatal:
		t.Fatalf("surviving listener returned a fatal accept error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("surviving listener never accepted a connection after its sibling was closed")
	}
}
