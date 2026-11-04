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
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestAbstractUnixSocketsDoNotUnlinkFilesystemPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract Unix sockets are Linux-specific")
	}

	for _, network := range []string{"unix", "unixgram"} {
		t.Run(network, func(t *testing.T) {
			sentinel, err := os.CreateTemp(".", "@caddy-abstract-*")
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Base(sentinel.Name())
			if err := sentinel.Close(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(name) })

			ln, err := (NetworkAddress{Network: network, Host: name}).Listen(
				context.Background(), 0, net.ListenConfig{})
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = ln.(io.Closer).Close()
				}
			})
			if _, err := os.Stat(name); err != nil {
				t.Fatalf("abstract listen removed sentinel: %v", err)
			}
			err = ln.(io.Closer).Close()
			closed = true
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(name); err != nil {
				t.Fatalf("abstract close removed sentinel: %v", err)
			}
		})
	}
}

func TestUnixListenerDoubleCloseDoesNotReleaseAnotherReference(t *testing.T) {
	socketPath := shortTempSocket(t)
	na := NetworkAddress{Network: "unix", Host: socketPath}

	firstAny, err := na.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	firstOuter := firstAny.(deleteListener)
	first := firstOuter.Listener.(*unixListener)
	var second *unixListener
	t.Cleanup(func() {
		_ = firstOuter.Close()
		if second != nil {
			_ = second.Close()
		}
	})
	secondAny, err := na.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	second = secondAny.(*unixListener)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close() error = %v; want net.ErrClosed", err)
	}
	if got := first.count.Load(); got != 1 {
		t.Fatalf("reference count = %d; want 1", got)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket used by second reference was removed: %v", err)
	}

	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnixConnDoubleCloseDoesNotReleaseAnotherReference(t *testing.T) {
	socketPath := shortTempSocket(t)
	na := NetworkAddress{Network: "unixgram", Host: socketPath}

	firstAny, err := na.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	firstOuter := firstAny.(deletePacketConn)
	first := firstOuter.PacketConn.(*unixConn)
	var second *unixConn
	t.Cleanup(func() {
		_ = firstOuter.Close()
		if second != nil {
			_ = second.Close()
		}
	})
	secondAny, err := na.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	second = secondAny.(*unixConn)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close() error = %v; want net.ErrClosed", err)
	}
	if got := first.count.Load(); got != 1 {
		t.Fatalf("reference count = %d; want 1", got)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket used by second reference was removed: %v", err)
	}

	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// shortTempSocket returns a short unix socket path to avoid sockaddr_un
// path length limits (104 bytes on Darwin/BSD, 108 bytes on Linux),
// which can be exceeded by t.TempDir() in deeply nested temp directories.
func shortTempSocket(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "c-*.sock")
	if err != nil {
		t.Fatalf("failed to create temp socket path: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path)
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

func TestUnixListenerClosesImmediatelyAndUnlinks(t *testing.T) {
	socketPath := shortTempSocket(t)
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
	socketPath := shortTempSocket(t)
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
	socketPath := shortTempSocket(t)
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

func TestUnixListenerConcurrentCloseAndRelisten(t *testing.T) {
	socketPath := shortTempSocket(t)
	na := NetworkAddress{Network: "unix", Host: socketPath}

	for i := 0; i < 20; i++ {
		ln, err := na.Listen(context.Background(), 0, net.ListenConfig{})
		if err != nil {
			t.Fatalf("iteration %d: initial listen failed: %v", i, err)
		}
		listener := ln.(net.Listener)

		var wg sync.WaitGroup
		wg.Add(2)

		var newLn net.Listener
		var listenErr error

		go func() {
			defer wg.Done()
			_ = listener.Close()
		}()

		go func() {
			defer wg.Done()
			ln2, err := na.Listen(context.Background(), 0, net.ListenConfig{})
			if err != nil {
				listenErr = err
				return
			}
			newLn = ln2.(net.Listener)
		}()

		wg.Wait()

		if listenErr != nil {
			t.Fatalf("iteration %d: concurrent listen failed: %v", i, listenErr)
		}

		if _, err := os.Stat(socketPath); err != nil {
			t.Fatalf("iteration %d: socket file does not exist after concurrent relisten: %v", i, err)
		}

		clientConn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("iteration %d: dialing concurrent listener failed: %v", i, err)
		}
		_ = clientConn.Close()

		_ = newLn.Close()
	}
}

func TestUnixConnConcurrentCloseAndRelisten(t *testing.T) {
	socketPath := shortTempSocket(t)
	na := NetworkAddress{Network: "unixgram", Host: socketPath}

	for i := 0; i < 20; i++ {
		pc, err := na.Listen(context.Background(), 0, net.ListenConfig{})
		if err != nil {
			t.Fatalf("iteration %d: initial listen failed: %v", i, err)
		}
		packetConn := pc.(net.PacketConn)

		var wg sync.WaitGroup
		wg.Add(2)

		var newPc net.PacketConn
		var listenErr error

		go func() {
			defer wg.Done()
			_ = packetConn.Close()
		}()

		go func() {
			defer wg.Done()
			pc2, err := na.Listen(context.Background(), 0, net.ListenConfig{})
			if err != nil {
				listenErr = err
				return
			}
			newPc = pc2.(net.PacketConn)
		}()

		wg.Wait()

		if listenErr != nil {
			t.Fatalf("iteration %d: concurrent listen failed: %v", i, listenErr)
		}

		if _, err := os.Stat(socketPath); err != nil {
			t.Fatalf("iteration %d: socket file does not exist after concurrent relisten: %v", i, err)
		}

		_ = newPc.Close()
	}
}
