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

package reverseproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"
)

// pumpTestTopology spins up:
//
//	client → frontend(Server F) → upstream(Server U)
//
// Server U is the real upstream; its handler is provided by the test.
// Server F's handler dials U and runs runWebTransportPump between the two
// sessions, so the client (who dials F) effectively talks to U through
// the pump.
type pumpTestTopology struct {
	frontendAddr *net.UDPAddr
	clientTLS    *tls.Config
	shutdown     func()
}

func newPumpTestTopology(t *testing.T, upstreamHandler func(*webtransport.Session, *http.Request)) *pumpTestTopology {
	t.Helper()

	uAddr, uRoot, uShutdown := startTestWebTransportServer(t, upstreamHandler)

	fAddr, fRoot, fShutdown := startTestWebTransportServer(t, func(clientSess *webtransport.Session, _ *http.Request) {
		// Dial U.
		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		url := fmt.Sprintf("https://localhost:%d/", uAddr.Port)
		_, upstreamSess, err := dialUpstreamWebTransport(dialCtx, clientTLSFor(uRoot), url, nil)
		if err != nil {
			t.Errorf("frontend: dial upstream: %v", err)
			_ = clientSess.CloseWithError(0, "upstream dial failed")
			return
		}
		runWebTransportPump(clientSess, upstreamSess, zap.NewNop())
	})

	return &pumpTestTopology{
		frontendAddr: fAddr,
		clientTLS:    clientTLSFor(fRoot),
		shutdown: func() {
			fShutdown()
			uShutdown()
		},
	}
}

// dialFrontend returns a fresh session dialed against the frontend server.
func (tt *pumpTestTopology) dialFrontend(t *testing.T) *webtransport.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://localhost:%d/", tt.frontendAddr.Port)
	_, sess, err := dialUpstreamWebTransport(ctx, tt.clientTLS, url, nil)
	if err != nil {
		t.Fatalf("client dial frontend: %v", err)
	}
	return sess
}

// echoUpstream is a ready-made upstream handler that echoes bytes on every
// bidirectional stream it's given.
func echoUpstream(sess *webtransport.Session, _ *http.Request) {
	ctx := sess.Context()
	for {
		str, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s *webtransport.Stream) {
			_, _ = io.Copy(s, s)
			_ = s.Close()
		}(str)
	}
}

func TestPump_BidiStreamClientToUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	tt := newPumpTestTopology(t, echoUpstream)
	t.Cleanup(tt.shutdown)

	sess := tt.dialFrontend(t)
	defer sess.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	const payload = "hello from client"
	if _, err := io.WriteString(str, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := str.Close(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

func TestPump_BidiStreamUpstreamToClient(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	// Upstream opens a stream toward the client and sends data.
	serverReady := make(chan struct{})
	const payload = "hello from upstream"
	tt := newPumpTestTopology(t, func(sess *webtransport.Session, _ *http.Request) {
		defer close(serverReady)
		ctx, cancel := context.WithTimeout(sess.Context(), 5*time.Second)
		defer cancel()
		str, err := sess.OpenStreamSync(ctx)
		if err != nil {
			t.Errorf("upstream open: %v", err)
			return
		}
		if _, err := io.WriteString(str, payload); err != nil {
			t.Errorf("upstream write: %v", err)
			return
		}
		_ = str.Close()
		// Keep the session alive briefly so the stream can be drained client-side.
		<-sess.Context().Done()
	})
	t.Cleanup(tt.shutdown)

	sess := tt.dialFrontend(t)
	defer sess.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := sess.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("client accept: %v", err)
	}
	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("bytes mismatch: got %q want %q", got, payload)
	}
}

func TestPump_UniStreamClientToUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	// Upstream: accept one uni stream and echo its bytes on a new uni stream
	// back to the client.
	const payload = "uni from client"
	tt := newPumpTestTopology(t, func(sess *webtransport.Session, _ *http.Request) {
		ctx := sess.Context()
		recv, err := sess.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		data, err := io.ReadAll(recv)
		if err != nil {
			t.Errorf("upstream read uni: %v", err)
			return
		}
		send, err := sess.OpenUniStreamSync(ctx)
		if err != nil {
			t.Errorf("upstream open uni: %v", err)
			return
		}
		if _, err := send.Write(data); err != nil {
			t.Errorf("upstream write uni: %v", err)
		}
		_ = send.Close()
		<-sess.Context().Done()
	})
	t.Cleanup(tt.shutdown)

	sess := tt.dialFrontend(t)
	defer sess.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sendStr, err := sess.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatalf("client open uni: %v", err)
	}
	if _, err := sendStr.Write([]byte(payload)); err != nil {
		t.Fatalf("client write uni: %v", err)
	}
	_ = sendStr.Close()

	recvStr, err := sess.AcceptUniStream(ctx)
	if err != nil {
		t.Fatalf("client accept uni: %v", err)
	}
	got, err := io.ReadAll(recvStr)
	if err != nil {
		t.Fatalf("client read uni: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("uni echo mismatch: got %q want %q", got, payload)
	}
}

func TestPump_Datagram(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	// Upstream echoes whatever datagram it receives.
	tt := newPumpTestTopology(t, func(sess *webtransport.Session, _ *http.Request) {
		ctx := sess.Context()
		for {
			d, err := sess.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			_ = sess.SendDatagram(d)
		}
	})
	t.Cleanup(tt.shutdown)

	sess := tt.dialFrontend(t)
	defer sess.CloseWithError(0, "")

	// Datagrams are unreliable. Retry a few times to get one round-trip.
	payload := []byte("dgram")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("no datagram echo observed within deadline")
		}
		if err := sess.SendDatagram(payload); err != nil {
			t.Fatalf("send datagram: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		got, err := sess.ReceiveDatagram(ctx)
		cancel()
		if err == nil && string(got) == string(payload) {
			return
		}
	}
}

func TestPump_CloseWithErrorPropagatesClientToUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	upstreamSawErr := make(chan error, 1)
	tt := newPumpTestTopology(t, func(sess *webtransport.Session, _ *http.Request) {
		// Use a fresh long-lived context so we don't race with
		// sess.Context() firing and getting a context error instead of
		// the session-level error.
		_, err := sess.AcceptStream(context.Background())
		upstreamSawErr <- err
	})
	t.Cleanup(tt.shutdown)

	sess := tt.dialFrontend(t)

	// Client closes with a specific code; pump should propagate to upstream.
	const code webtransport.SessionErrorCode = 4242
	const msg = "client bye"
	if err := sess.CloseWithError(code, msg); err != nil {
		t.Fatalf("client close: %v", err)
	}

	select {
	case err := <-upstreamSawErr:
		if err == nil {
			t.Fatal("upstream expected error after client close; got nil")
		}
		// Close propagation is best-effort for a client-initiated close:
		// webtransport-go's Dialer tears down the dedicated QUIC connection
		// immediately after CloseWithError, and on the pump's server-side
		// session the WT_CLOSE_SESSION capsule can lose the race to the
		// QUIC close — in which case parseNextCapsule stores a non-
		// SessionError and the code is unrecoverable. The invariant we
		// can reliably enforce is "upstream observed a session-terminating
		// error." If the code did survive, assert it matches.
		var sessErr *webtransport.SessionError
		if errors.As(err, &sessErr) && sessErr.ErrorCode != 0 {
			if sessErr.ErrorCode != code || sessErr.Message != msg {
				t.Errorf("upstream saw code=%d msg=%q, want code=%d msg=%q",
					sessErr.ErrorCode, sessErr.Message, code, msg)
			}
		} else {
			t.Logf("upstream saw %T: %v (code lost to QUIC-close race; close propagation itself is verified)", err, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not observe close in time")
	}
}

func TestPump_CloseWithErrorPropagatesUpstreamToClient(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	const code webtransport.SessionErrorCode = 9000
	const msg = "upstream bye"
	tt := newPumpTestTopology(t, func(sess *webtransport.Session, _ *http.Request) {
		_ = sess.CloseWithError(code, msg)
	})
	t.Cleanup(tt.shutdown)

	sess := tt.dialFrontend(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := sess.AcceptStream(ctx)
	var sessErr *webtransport.SessionError
	if !errors.As(err, &sessErr) {
		t.Fatalf("expected SessionError, got %T: %v", err, err)
	}
	if sessErr.ErrorCode != code || sessErr.Message != msg {
		t.Errorf("client saw code=%d msg=%q, want code=%d msg=%q",
			sessErr.ErrorCode, sessErr.Message, code, msg)
	}
}

// TestPump_SessionLifecycle_NoGoroutineLeak sanity-checks that after both
// sessions end, the pump's goroutines unwind. We compare goroutine counts
// before and after, with a small tolerance because the Go runtime has
// background goroutines we can't synchronize with.
func TestPump_SessionLifecycle_NoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	before := runtime.NumGoroutine()

	// Drive a fast session+close cycle.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tt := newPumpTestTopology(t, echoUpstream)
		sess := tt.dialFrontend(t)
		_ = sess.CloseWithError(0, "")
		// Allow close to propagate and goroutines to exit.
		time.Sleep(200 * time.Millisecond)
		tt.shutdown()
	}()
	wg.Wait()

	// Give the runtime a moment to finish tearing down.
	deadline := time.Now().Add(2 * time.Second)
	var after int
	for {
		after = runtime.NumGoroutine()
		if after <= before+8 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Allow some slack — test infrastructure itself keeps a few goroutines.
	if after > before+16 {
		t.Errorf("possible goroutine leak: before=%d after=%d", before, after)
	}
}
