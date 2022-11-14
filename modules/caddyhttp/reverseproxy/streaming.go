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

// Most of the code in this file was initially borrowed from the Go
// standard library and modified; It had this copyright notice:
// Copyright 2011 The Go Authors

package reverseproxy

import (
	"context"
	"io"
	weakrand "math/rand"
	"mime"
	"net/http"
	"sync"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

func (h Handler) handleUpgradeResponse(logger *zap.Logger, rw http.ResponseWriter, req *http.Request, res *http.Response) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)

	// Taken from https://github.com/golang/go/commit/5c489514bc5e61ad9b5b07bd7d8ec65d66a0512a
	// We know reqUpType is ASCII, it's checked by the caller.
	if !asciiIsPrint(resUpType) {
		h.logger.Debug("backend tried to switch to invalid protocol",
			zap.String("backend_upgrade", resUpType))
		return
	}
	if !asciiEqualFold(reqUpType, resUpType) {
		h.logger.Debug("backend tried to switch to unexpected protocol via Upgrade header",
			zap.String("backend_upgrade", resUpType),
			zap.String("requested_upgrade", reqUpType))
		return
	}

	hj, ok := rw.(http.Hijacker)
	if !ok {
		h.logger.Sugar().Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw)
		return
	}
	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		h.logger.Error("internal error: 101 switching protocols response with non-writable body")
		return
	}

	// adopted from https://github.com/golang/go/commit/8bcf2834afdf6a1f7937390903a41518715ef6f5
	backConnCloseCh := make(chan struct{})
	go func() {
		// Ensure that the cancelation of a request closes the backend.
		// See issue https://golang.org/issue/35559.
		select {
		case <-req.Context().Done():
		case <-backConnCloseCh:
		}
		backConn.Close()
	}()
	defer close(backConnCloseCh)

	logger.Debug("upgrading connection")
	conn, brw, err := hj.Hijack()
	if err != nil {
		h.logger.Error("hijack failed on protocol switch", zap.Error(err))
		return
	}
	defer conn.Close()

	start := time.Now()
	defer func() {
		logger.Debug("connection closed", zap.Duration("duration", time.Since(start)))
	}()

	copyHeader(rw.Header(), res.Header)

	res.Header = rw.Header()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		h.logger.Debug("response write", zap.Error(err))
		return
	}
	if err := brw.Flush(); err != nil {
		h.logger.Debug("response flush", zap.Error(err))
		return
	}

	// Ensure the hijacked client connection, and the new connection established
	// with the backend, are both closed in the event of a server shutdown. This
	// is done by registering them. We also try to gracefully close connections
	// we recognize as websockets.
	// We need to make sure the client connection messages (i.e. to upstream)
	// are masked, so we need to know whether the connection is considered the
	// server or the client side of the proxy.
	gracefulClose := func(conn io.ReadWriteCloser, isClient bool) func() error {
		if isWebsocket(req) {
			return func() error {
				return writeCloseControl(conn, isClient)
			}
		}
		return nil
	}
	deleteFrontConn := h.registerConnection(conn, gracefulClose(conn, false))
	deleteBackConn := h.registerConnection(backConn, gracefulClose(backConn, true))
	defer deleteFrontConn()
	defer deleteBackConn()

	spc := switchProtocolCopier{user: conn, backend: backConn}

	errc := make(chan error, 1)
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (h Handler) flushInterval(req *http.Request, res *http.Response) time.Duration {
	resCTHeader := res.Header.Get("Content-Type")
	resCT, _, err := mime.ParseMediaType(resCTHeader)

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if err == nil && resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// We might have the case of streaming for which Content-Length might be unset.
	if res.ContentLength == -1 {
		return -1
	}

	// for h2 and h2c upstream streaming data to client (issues #3556 and #3606)
	if h.isBidirectionalStream(req, res) {
		return -1
	}

	return time.Duration(h.FlushInterval)
}

// isBidirectionalStream returns whether we should work in bi-directional stream mode.
//
// See https://github.com/caddyserver/caddy/pull/3620 for discussion of nuances.
func (h Handler) isBidirectionalStream(req *http.Request, res *http.Response) bool {
	// We have to check the encoding here; only flush headers with identity encoding.
	// Non-identity encoding might combine with "encode" directive, and in that case,
	// if body size larger than enc.MinLength, upper level encode handle might have
	// Content-Encoding header to write.
	// (see https://github.com/caddyserver/caddy/issues/3606 for use case)
	ae := req.Header.Get("Accept-Encoding")

	return req.ProtoMajor == 2 &&
		res.ProtoMajor == 2 &&
		res.ContentLength == -1 &&
		(ae == "identity" || ae == "")
}

func (h Handler) copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()

			// set up initial timer so headers get flushed even if body writes are delayed
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

			dst = mlw
		}
	}

	buf := streamingBufPool.Get().(*[]byte)
	defer streamingBufPool.Put(buf)
	_, err := h.copyBuffer(dst, src, *buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (h Handler) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, defaultBufferSize)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			// TODO: this could be useful to know (indeed, it revealed an error in our
			// fastcgi PoC earlier; but it's this single error report here that necessitates
			// a function separate from io.CopyBuffer, since io.CopyBuffer does not distinguish
			// between read or write errors; in a reverse proxy situation, write errors are not
			// something we need to report to the client, but read errors are a problem on our
			// end for sure. so we need to decide what we want.)
			// p.logf("copyBuffer: ReverseProxy read error during body copy: %v", rerr)
			h.logger.Error("reading from backend", zap.Error(rerr))
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

// registerConnection holds onto conn so it can be closed in the event
// of a server shutdown. This is useful because hijacked connections or
// connections dialed to backends don't close when server is shut down.
// The caller should call the returned delete() function when the
// connection is done to remove it from memory.
func (h *Handler) registerConnection(conn io.ReadWriteCloser, gracefulClose func() error) (del func()) {
	h.connectionsMu.Lock()
	h.connections[conn] = openConnection{conn, gracefulClose}
	h.connectionsMu.Unlock()
	return func() {
		h.connectionsMu.Lock()
		delete(h.connections, conn)
		h.connectionsMu.Unlock()
	}
}

// writeCloseControl sends a best-effort Close control message to the given
// WebSocket connection. Thanks to @pascaldekloe who provided inspiration
// from his simple implementation of this I was able to learn from at:
// github.com/pascaldekloe/websocket. Further work for handling masking
// taken from github.com/gorilla/websocket.
func writeCloseControl(conn io.Writer, isClient bool) error {
	// Sources:
	// https://github.com/pascaldekloe/websocket/blob/32050af67a5d/websocket.go#L119
	// https://github.com/gorilla/websocket/blob/v1.5.0/conn.go#L413

	// For now, we're not using a reason. We might later, though.
	// The code handling the reason is left in
	var reason string // max 123 bytes (control frame payload limit is 125; status code takes 2)

	const closeMessage = 8
	const finalBit = 1 << 7 // Frame header byte 0 bits from Section 5.2 of RFC 6455
	const maskBit = 1 << 7  // Frame header byte 1 bits from Section 5.2 of RFC 6455
	const goingAwayUpper uint8 = 1001 >> 8
	const goingAwayLower uint8 = 1001 & 0xff

	b0 := byte(closeMessage) | finalBit
	b1 := byte(len(reason) + 2)
	if isClient {
		b1 |= maskBit
	}

	buf := make([]byte, 0, 127)
	buf = append(buf, b0, b1)
	msgLength := 4 + len(reason)

	// Both branches below append the "going away" code and reason
	appendMessage := func(buf []byte) []byte {
		buf = append(buf, goingAwayUpper, goingAwayLower)
		buf = append(buf, []byte(reason)...)
		return buf
	}

	// When we're the client, we need to mask the message as per
	// https://www.rfc-editor.org/rfc/rfc6455#section-5.3
	if isClient {
		key := newMaskKey()
		buf = append(buf, key[:]...)
		msgLength += len(key)
		buf = appendMessage(buf)
		maskBytes(key, 0, buf[2+len(key):])
	} else {
		buf = appendMessage(buf)
	}

	// simply best-effort, but return error for logging purposes
	// TODO: we might need to ensure we are the exclusive writer by this point (io.Copy is stopped)?
	_, err := conn.Write(buf[:msgLength])
	return err
}

// Copied from https://github.com/gorilla/websocket/blob/v1.5.0/mask.go
func maskBytes(key [4]byte, pos int, b []byte) int {
	// Mask one byte at a time for small buffers.
	if len(b) < 2*wordSize {
		for i := range b {
			b[i] ^= key[pos&3]
			pos++
		}
		return pos & 3
	}

	// Mask one byte at a time to word boundary.
	if n := int(uintptr(unsafe.Pointer(&b[0]))) % wordSize; n != 0 {
		n = wordSize - n
		for i := range b[:n] {
			b[i] ^= key[pos&3]
			pos++
		}
		b = b[n:]
	}

	// Create aligned word size key.
	var k [wordSize]byte
	for i := range k {
		k[i] = key[(pos+i)&3]
	}
	kw := *(*uintptr)(unsafe.Pointer(&k))

	// Mask one word at a time.
	n := (len(b) / wordSize) * wordSize
	for i := 0; i < n; i += wordSize {
		*(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) ^= kw
	}

	// Mask one byte at a time for remaining bytes.
	b = b[n:]
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}

	return pos & 3
}

// Copied from https://github.com/gorilla/websocket/blob/v1.5.0/conn.go#L184
func newMaskKey() [4]byte {
	n := weakrand.Uint32()
	return [4]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}

// isWebsocket returns true if r looks to be an upgrade request for WebSockets.
// It is a fairly naive check.
func isWebsocket(r *http.Request) bool {
	return httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade") &&
		httpguts.HeaderValuesContainsToken(r.Header["Upgrade"], "websocket")
}

// openConnection maps an open connection to
// an optional function for graceful close.
type openConnection struct {
	conn          io.ReadWriteCloser
	gracefulClose func() error
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriteCloser
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
}

var streamingBufPool = sync.Pool{
	New: func() any {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation
		// - (from the package docs)
		b := make([]byte, defaultBufferSize)
		return &b
	},
}

const defaultBufferSize = 32 * 1024
const wordSize = int(unsafe.Sizeof(uintptr(0)))
