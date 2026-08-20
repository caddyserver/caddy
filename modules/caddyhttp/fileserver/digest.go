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

package fileserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// normalizeContentDigestAlgos validates supported algorithms and removes duplicates.
// Canonical names follow the IANA "Hash Algorithms for HTTP Digest Fields" registry
// (RFC 9530): "sha-256", "sha-512".
func normalizeContentDigestAlgos(algos []string) ([]string, error) {
	if len(algos) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(algos))
	out := make([]string, 0, len(algos))
	for _, algo := range algos {
		canonical, err := canonicalContentDigestAlgo(algo)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

func canonicalContentDigestAlgo(algo string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "sha-256", "sha256":
		return "sha-256", nil
	case "sha-512", "sha512":
		return "sha-512", nil
	case "":
		return "", fmt.Errorf("content digest algorithm must not be empty")
	default:
		return "", fmt.Errorf("unsupported content digest algorithm %q (supported: sha-256, sha-512)", algo)
	}
}

func newContentDigestHash(algo string) (hash.Hash, error) {
	switch algo {
	case "sha-256":
		return sha256.New(), nil
	case "sha-512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported content digest algorithm %q", algo)
	}
}

// formatContentDigest builds an RFC 9530 Content-Digest Structured Fields
// dictionary over content for the configured algorithms. All algorithms are
// fed in a single pass via io.MultiWriter.
func formatContentDigest(algos []string, content []byte) (string, error) {
	if len(algos) == 0 {
		return "", nil
	}
	hashers := make([]hash.Hash, len(algos))
	writers := make([]io.Writer, len(algos))
	for i, algo := range algos {
		h, err := newContentDigestHash(algo)
		if err != nil {
			return "", err
		}
		hashers[i] = h
		writers[i] = h
	}
	if len(content) > 0 {
		if _, err := io.MultiWriter(writers...).Write(content); err != nil {
			return "", fmt.Errorf("content digest: hash content: %w", err)
		}
	}
	var parts []string
	for i, algo := range algos {
		digest := base64.StdEncoding.EncodeToString(hashers[i].Sum(nil))
		parts = append(parts, algo+"=:"+digest+":")
	}
	return strings.Join(parts, ", "), nil
}

// contentDigestResponseWriter buffers the body http.ServeContent writes (up to
// maxBuffer), then attaches Content-Digest over those exact bytes before
// flushing the response. If the body would exceed maxBuffer—either by
// Content-Length or while writing—the writer switches to a non-buffering
// passthrough and omits Content-Digest.
//
// Digest is emitted for 200 and 206 when Content-Encoding is absent or matches
// a static precompressed sidecar; 304/416/other statuses omit it. HEAD 200
// yields the empty-content digest (RFC 9530 Appendix B.2).
type contentDigestResponseWriter struct {
	http.ResponseWriter
	algos       []string
	precompress string
	maxBuffer   int64
	isHead      bool
	status      int
	statusSet   bool
	flushed     bool
	omitDigest  bool
	buf         bytes.Buffer
}

func (cd *contentDigestResponseWriter) WriteHeader(status int) {
	if cd.flushed {
		cd.ResponseWriter.WriteHeader(status)
		return
	}
	if !cd.statusSet {
		cd.status = status
		cd.statusSet = true
	}
	// If ServeContent already advertised a body larger than the buffer budget,
	// stream without digest instead of buffering. This only applies to requests
	// with a body (not HEAD, where Content-Length describes the representation
	// payload but no body bytes are buffered or sent).
	if !cd.isHead && !cd.omitDigest && cd.maxBuffer > 0 {
		if cl := cd.Header().Get("Content-Length"); cl != "" {
			if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n > cd.maxBuffer {
				cd.omitDigest = true
			}
		}
	}
	if cd.omitDigest {
		if err := cd.switchToPassthrough(); err != nil {
			// WriteHeader cannot return an error; surface on the next Write.
			return
		}
	}
}

func (cd *contentDigestResponseWriter) Write(b []byte) (int, error) {
	if cd.flushed {
		return cd.ResponseWriter.Write(b)
	}
	if !cd.statusSet {
		cd.WriteHeader(http.StatusOK)
		if cd.flushed {
			return cd.ResponseWriter.Write(b)
		}
	}
	if cd.maxBuffer > 0 && int64(cd.buf.Len())+int64(len(b)) > cd.maxBuffer {
		cd.omitDigest = true
		if err := cd.switchToPassthrough(); err != nil {
			return 0, err
		}
		return cd.ResponseWriter.Write(b)
	}
	return cd.buf.Write(b)
}

// ReadFrom buffers r through Write so sendfile/ReadFrom paths still contribute
// to the Content-Digest snapshot while the size limit is enforced. After a
// passthrough switch, the underlying ReaderFrom is used when available.
//
// While still buffering we must not call io.Copy(cd, r): Copy prefers
// ReaderFrom and would recurse into this method.
func (cd *contentDigestResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if cd.flushed {
		if rf, ok := cd.ResponseWriter.(io.ReaderFrom); ok {
			return rf.ReadFrom(r)
		}
		return io.Copy(cd.ResponseWriter, r)
	}
	return io.Copy(struct{ io.Writer }{cd}, r)
}

// switchToPassthrough flushes any buffered bytes without a Content-Digest and
// sends the real status line so subsequent writes stream to the client.
func (cd *contentDigestResponseWriter) switchToPassthrough() error {
	if cd.flushed {
		return nil
	}
	cd.flushed = true
	cd.omitDigest = true
	cd.Header().Del("Content-Digest")

	status := cd.status
	if !cd.statusSet {
		status = http.StatusOK
	}
	cd.ResponseWriter.WriteHeader(status)
	if cd.buf.Len() == 0 {
		return nil
	}
	_, err := cd.ResponseWriter.Write(cd.buf.Bytes())
	cd.buf.Reset()
	return err
}

// finalize hashes the buffered message content, sets or clears Content-Digest,
// then writes the real status line and body to the underlying ResponseWriter.
// No-op if the body was already streamed via the over-limit passthrough path.
func (cd *contentDigestResponseWriter) finalize() error {
	if cd.flushed {
		return nil
	}
	cd.flushed = true

	status := cd.status
	if !cd.statusSet {
		status = http.StatusOK
	}

	enc := cd.Header().Get("Content-Encoding")
	allowDigest := !cd.omitDigest &&
		(status == http.StatusOK || status == http.StatusPartialContent) &&
		(enc == "" || enc == cd.precompress)
	if allowDigest {
		digest, err := formatContentDigest(cd.algos, cd.buf.Bytes())
		if err != nil {
			return err
		}
		if digest != "" {
			cd.Header().Set("Content-Digest", digest)
		}
	} else {
		cd.Header().Del("Content-Digest")
	}

	cd.ResponseWriter.WriteHeader(status)
	if cd.buf.Len() == 0 {
		return nil
	}
	_, err := cd.ResponseWriter.Write(cd.buf.Bytes())
	return err
}

func (cd *contentDigestResponseWriter) Unwrap() http.ResponseWriter {
	return cd.ResponseWriter
}
