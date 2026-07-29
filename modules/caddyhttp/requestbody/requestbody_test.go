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

package requestbody

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// pacedReader emits chunkCount chunks of chunkSize bytes, sleeping delay
// before each one, simulating a client that trickles a request body.
type pacedReader struct {
	delay      time.Duration
	chunkSize  int
	chunkCount int
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if p.chunkCount <= 0 {
		return 0, io.EOF
	}
	time.Sleep(p.delay)
	p.chunkCount--
	n := copy(b, make([]byte, p.chunkSize))
	return n, nil
}

// noError adapts a caddyhttp.Handler to a plain http.Handler for httptest.NewServer.
func noError(h caddyhttp.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h.ServeHTTP(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func TestRequestBody_ReadTimeoutIsIdleReset(t *testing.T) {
	const timeout = 150 * time.Millisecond

	rb := RequestBody{ReadTimeout: timeout}
	rb.logger = zap.NewNop()

	srv := httptest.NewServer(noError(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return rb.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			_, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusRequestTimeout)
				return nil
			}
			w.WriteHeader(http.StatusOK)
			return nil
		}))
	})))
	defer srv.Close()

	// each gap is well under timeout, but the cumulative transfer time
	// is well over it; a hard (non-idle-reset) deadline would kill this
	body := &pacedReader{delay: timeout / 4, chunkSize: 8, chunkCount: 8}
	resp, err := http.Post(srv.URL, "application/octet-stream", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequestBody_WriteMaxChunkOverride(t *testing.T) {
	const size = 10000
	const maxChunk = 100

	rb := RequestBody{WriteTimeout: time.Second, MaxWriteChunk: maxChunk}
	rb.logger = zap.NewNop()

	srv := httptest.NewServer(noError(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return rb.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			_, err := w.Write(make([]byte, size))
			return err
		}))
	})))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	assert.EqualValues(t, size, n)
}
