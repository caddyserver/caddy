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
	"errors"
	"io"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"
)

// runWebTransportPump bridges two WebTransport sessions so that every
// bidirectional stream, unidirectional stream, and datagram opened on one
// side is mirrored onto the other. It blocks until both sessions end.
//
// Close propagation: when either session ends with a SessionError, the
// error code and message are forwarded to the peer via CloseWithError.
// When a session ends without a SessionError (context cancelled or
// connection dropped), the peer is closed with code 0. Each side's close
// is propagated at most once.
//
// EXPERIMENTAL: this helper is an internal building block for the
// WebTransport reverse-proxy transport and may change.
func runWebTransportPump(clientSess, upstreamSess *webtransport.Session, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	p := &webtransportPump{
		client:   clientSess,
		upstream: upstreamSess,
		logger:   logger,
	}
	p.run()
}

type webtransportPump struct {
	client, upstream *webtransport.Session
	logger           *zap.Logger

	closeClientOnce   sync.Once
	closeUpstreamOnce sync.Once
}

func (p *webtransportPump) run() {
	var wg sync.WaitGroup
	wg.Add(6)

	// Bidirectional streams in both directions.
	go func() { defer wg.Done(); p.acceptBidi(p.client, p.upstream, p.closeUpstream) }()
	go func() { defer wg.Done(); p.acceptBidi(p.upstream, p.client, p.closeClient) }()

	// Unidirectional streams in both directions.
	go func() { defer wg.Done(); p.acceptUni(p.client, p.upstream, p.closeUpstream) }()
	go func() { defer wg.Done(); p.acceptUni(p.upstream, p.client, p.closeClient) }()

	// Datagrams in both directions.
	go func() { defer wg.Done(); p.pumpDatagrams(p.client, p.upstream, p.closeUpstream) }()
	go func() { defer wg.Done(); p.pumpDatagrams(p.upstream, p.client, p.closeClient) }()

	wg.Wait()
}

func (p *webtransportPump) closeClient(cause error) {
	p.propagateClose(p.client, p.upstream, &p.closeClientOnce, cause)
}

func (p *webtransportPump) closeUpstream(cause error) {
	p.propagateClose(p.upstream, p.client, &p.closeUpstreamOnce, cause)
}

// propagateClose closes target once with a code/message derived from
// cause. If cause carries a *webtransport.SessionError (the common case —
// Accept{,Uni}Stream returns it directly when the peer closed the
// session), its code/message are used. Otherwise, typically the
// datagram loop won the race to detect the close and its error lacks
// the code, so we fall back to probing peer for its stored close state
// via a short AcceptStream.
func (p *webtransportPump) propagateClose(target, peer *webtransport.Session, once *sync.Once, cause error) {
	once.Do(func() {
		code, msg, ok := closeCodeFromErr(cause)
		if !ok {
			code, msg, _ = codeFromSession(peer)
		}
		_ = target.CloseWithError(code, msg)
	})
}

// codeFromSession reads the peer's stored SessionError by waiting for the
// session's context to be cancelled — by that point webtransport-go has
// set closeErr — and then calling AcceptStream, which returns it via its
// initial closeErr check without blocking. Used only on the close path
// when the caller's own error didn't carry the code (e.g. ReceiveDatagram
// returned a context error).
func codeFromSession(sess *webtransport.Session) (webtransport.SessionErrorCode, string, bool) {
	select {
	case <-sess.Context().Done():
	case <-time.After(200 * time.Millisecond):
		return 0, "", false
	}
	_, err := sess.AcceptStream(context.Background())
	return closeCodeFromErr(err)
}

// acceptBidi loops on src.AcceptStream and, for each accepted
// bidirectional stream, opens a matching stream on dst and pipes bytes in
// both directions. When src ends, it invokes propagate to close dst.
func (p *webtransportPump) acceptBidi(src, dst *webtransport.Session, propagate func(error)) {
	ctx := src.Context()
	for {
		srcStr, err := src.AcceptStream(ctx)
		if err != nil {
			propagate(err)
			return
		}
		dstStr, err := dst.OpenStreamSync(ctx)
		if err != nil {
			p.logger.Debug("webtransport: open upstream bidi failed", zap.Error(err))
			srcStr.CancelRead(0)
			srcStr.CancelWrite(0)
			propagate(err)
			return
		}
		go p.spliceBidi(srcStr, dstStr)
	}
}

// spliceBidi copies bytes between two bidirectional streams until both
// sides observe EOF or an error.
func (p *webtransportPump) spliceBidi(a, b *webtransport.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(b, a); err != nil && !isExpectedEOF(err) {
			p.logger.Debug("webtransport bidi splice a->b", zap.Error(err))
		}
		_ = b.Close()
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(a, b); err != nil && !isExpectedEOF(err) {
			p.logger.Debug("webtransport bidi splice b->a", zap.Error(err))
		}
		_ = a.Close()
	}()
	wg.Wait()
}

// acceptUni loops on src.AcceptUniStream and, for each stream, opens a
// matching unidirectional stream on dst and pipes bytes through.
func (p *webtransportPump) acceptUni(src, dst *webtransport.Session, propagate func(error)) {
	ctx := src.Context()
	for {
		recv, err := src.AcceptUniStream(ctx)
		if err != nil {
			propagate(err)
			return
		}
		send, err := dst.OpenUniStreamSync(ctx)
		if err != nil {
			p.logger.Debug("webtransport: open upstream uni failed", zap.Error(err))
			recv.CancelRead(0)
			propagate(err)
			return
		}
		go func() {
			if _, err := io.Copy(send, recv); err != nil && !isExpectedEOF(err) {
				p.logger.Debug("webtransport uni splice", zap.Error(err))
			}
			_ = send.Close()
		}()
	}
}

// pumpDatagrams forwards datagrams from src to dst until src ends. Unlike
// streams, datagrams are unreliable, so SendDatagram errors are best-effort
// and are not treated as fatal for the session.
func (p *webtransportPump) pumpDatagrams(src, dst *webtransport.Session, propagate func(error)) {
	ctx := src.Context()
	for {
		data, err := src.ReceiveDatagram(ctx)
		if err != nil {
			propagate(err)
			return
		}
		if err := dst.SendDatagram(data); err != nil {
			p.logger.Debug("webtransport send datagram", zap.Error(err))
		}
	}
}

// closeCodeFromErr extracts a SessionErrorCode + message from err if it
// represents a session close. The bool is false when err is nil or not
// a *webtransport.SessionError.
func closeCodeFromErr(err error) (webtransport.SessionErrorCode, string, bool) {
	var sessErr *webtransport.SessionError
	if errors.As(err, &sessErr) {
		return sessErr.ErrorCode, sessErr.Message, true
	}
	return 0, "", false
}

// isExpectedEOF reports whether err is one we don't need to log: plain
// EOF, context cancellation, or an already-closed session.
func isExpectedEOF(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var sessErr *webtransport.SessionError
	return errors.As(err, &sessErr)
}
