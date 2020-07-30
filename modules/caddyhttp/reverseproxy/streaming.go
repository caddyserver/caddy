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
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

func (h Handler) handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if reqUpType != resUpType {
		// TODO: figure out our own error handling
		// p.getErrorHandler()(rw, req, fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType))
		return
	}

	copyHeader(res.Header, rw.Header())

	hj, ok := rw.(http.Hijacker)
	if !ok {
		// p.getErrorHandler()(rw, req, fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw))
		return
	}
	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		// p.getErrorHandler()(rw, req, fmt.Errorf("internal error: 101 switching protocols response with non-writable body"))
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

	conn, brw, err := hj.Hijack()
	if err != nil {
		// p.getErrorHandler()(rw, req, fmt.Errorf("Hijack failed on protocol switch: %v", err))
		return
	}
	defer conn.Close()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		// p.getErrorHandler()(rw, req, fmt.Errorf("response write: %v", err))
		return
	}
	if err := brw.Flush(); err != nil {
		// p.getErrorHandler()(rw, req, fmt.Errorf("response flush: %v", err))
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (h Handler) flushInterval(req *http.Request, res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// for h2 and h2c upstream streaming data to client (issue #3556,#3606)
	if req.ProtoMajor == 2 && res.ContentLength == -1 && req.Header.Get("Accept-Encoding") == "identity" {
		return -1
	}

	// TODO: more specific cases? e.g. res.ContentLength == -1? (this TODO is from the std lib)
	return time.Duration(h.FlushInterval)
}

func (h Handler) copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()
			dst = mlw
		}
	}

	buf := streamingBufPool.Get().([]byte)
	defer streamingBufPool.Put(buf)
	_, err := h.copyBuffer(dst, src, buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (h Handler) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
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
	user, backend io.ReadWriter
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
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}
