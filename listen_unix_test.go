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

//go:build unix && !solaris

package caddy

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixListenerClosesImmediatelyAndUnlinks(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test_listener.sock")
	lnKey := listenerKey("unix", socketPath)

	ctx := context.Background()
	rawLn, err := listenReusable(ctx, lnKey, "unix", socketPath, net.ListenConfig{})
	if err != nil {
		t.Fatalf("listenReusable failed: %v", err)
	}

	ln, ok := rawLn.(net.Listener)
	if !ok {
		t.Fatalf("expected net.Listener, got %T", rawLn)
	}

	// Verify socket file was created on disk
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("expected socket file to exist on disk: %v", err)
	}

	// Verify we can connect and accept
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	clientConn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial unix socket: %v", err)
	}
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept")
	}

	// Close the listener
	if err := ln.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	// The socket file must be removed immediately
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket file to be unlinked after Close, but stat returned: %v", err)
	}

	// Dialing the closed socket path must fail immediately and not hang
	dialErrChan := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
		}
		dialErrChan <- err
	}()

	select {
	case err := <-dialErrChan:
		if err == nil {
			t.Fatal("expected dial to fail on closed socket, but succeeded")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("dialing closed socket hung instead of failing immediately")
	}
}

func TestUnixConnClosesImmediatelyAndUnlinks(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test_conn.sock")
	lnKey := listenerKey("unixgram", socketPath)

	ctx := context.Background()
	rawConn, err := listenReusable(ctx, lnKey, "unixgram", socketPath, net.ListenConfig{})
	if err != nil {
		t.Fatalf("listenReusable failed: %v", err)
	}

	closer, ok := rawConn.(io.Closer)
	if !ok {
		t.Fatalf("expected io.Closer, got %T", rawConn)
	}

	// Verify socket file was created on disk
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("expected socket file to exist on disk: %v", err)
	}

	// Close the datagram conn
	if err := closer.Close(); err != nil {
		t.Fatalf("failed to close unixgram connection: %v", err)
	}

	// The socket file must be removed immediately
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket file to be unlinked after Close, but stat returned: %v", err)
	}
}

func TestUnixListenerReuseAndUnlinkOnlyWhenZeroCount(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test_reuse.sock")
	lnKey := listenerKey("unix", socketPath)

	ctx := context.Background()
	rawLn1, err := listenReusable(ctx, lnKey, "unix", socketPath, net.ListenConfig{})
	if err != nil {
		t.Fatalf("listenReusable failed: %v", err)
	}
	ln1 := rawLn1.(net.Listener)

	// Reuse socket
	rawLn2, err := reuseUnixSocket("unix", socketPath)
	if err != nil {
		t.Fatalf("reuseUnixSocket failed: %v", err)
	}
	ln2 := rawLn2.(net.Listener)

	// Close ln1: count drops to 1, socket must still exist
	if err := ln1.Close(); err != nil {
		t.Fatalf("ln1.Close() failed: %v", err)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("expected socket file to still exist after closing 1 of 2 references: %v", err)
	}

	// Close ln2: count drops to 0, socket file must be unlinked
	if err := ln2.Close(); err != nil {
		t.Fatalf("ln2.Close() failed: %v", err)
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket file to be unlinked after closing all references, got: %v", err)
	}
}
