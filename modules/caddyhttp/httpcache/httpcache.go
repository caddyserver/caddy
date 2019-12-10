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

package httpcache

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang/groupcache"
)

func init() {
	caddy.RegisterModule(Cache{})
}

// Cache implements a simple distributed cache.
type Cache struct {
	Self    string   `json:"self,omitempty"`
	Peers   []string `json:"peers,omitempty"`
	MaxSize int64    `json:"max_size,omitempty"`
	group   *groupcache.Group
}

// CaddyModule returns the Caddy module information.
func (Cache) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cache",
		New: func() caddy.Module { return new(Cache) },
	}
}

// Provision provisions c.
func (c *Cache) Provision(ctx caddy.Context) error {
	// TODO: use UsagePool so that cache survives config reloads - TODO: a single cache for whole process?
	maxSize := c.MaxSize
	if maxSize == 0 {
		const maxMB = 512
		maxSize = int64(maxMB << 20)
	}
	poolMu.Lock()
	if pool == nil {
		pool = groupcache.NewHTTPPool(c.Self)
		c.group = groupcache.NewGroup(groupName, maxSize, groupcache.GetterFunc(c.getter))
	} else {
		c.group = groupcache.GetGroup(groupName)
	}
	pool.Set(append(c.Peers, c.Self)...)
	poolMu.Unlock()

	return nil
}

// Validate validates c.
func (c *Cache) Validate() error {
	if c.Self == "" {
		return fmt.Errorf("address of this instance (self) is required")
	}
	if c.MaxSize < 0 {
		return fmt.Errorf("size must be greater than 0")
	}
	return nil
}

func (c *Cache) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// TODO: proper RFC implementation of cache control headers...
	if r.Header.Get("Cache-Control") == "no-cache" || (r.Method != "GET" && r.Method != "HEAD") {
		return next.ServeHTTP(w, r)
	}

	ctx := getterContext{w, r, next}

	// TODO: rigorous performance testing

	// TODO: pretty much everything else to handle the nuances of HTTP caching...

	// TODO: groupcache has no explicit cache eviction, so we need to embed
	// all information related to expiring cache entries into the key; right
	// now we just use the request URI as a proof-of-concept
	key := r.RequestURI

	var cachedBytes []byte
	err := c.group.Get(ctx, key, groupcache.AllocatingByteSliceSink(&cachedBytes))
	if err == errUncacheable {
		return nil
	}
	if err != nil {
		return err
	}

	// the cached bytes consists of two parts: first a
	// gob encoding of the status and header, immediately
	// followed by the raw bytes of the response body
	rdr := bytes.NewReader(cachedBytes)

	// read the header and status first
	var hs headerAndStatus
	err = gob.NewDecoder(rdr).Decode(&hs)
	if err != nil {
		return err
	}

	// set and write the cached headers
	for k, v := range hs.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(hs.Status)

	// write the cached response body
	io.Copy(w, rdr)

	return nil
}

func (c *Cache) getter(ctx groupcache.Context, key string, dest groupcache.Sink) error {
	combo := ctx.(getterContext)

	// the buffer will store the gob-encoded header, then the body
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	// we need to record the response if we are to cache it; only cache if
	// request is successful (TODO: there's probably much more nuance needed here)
	rr := caddyhttp.NewResponseRecorder(combo.rw, buf, func(status int, header http.Header) bool {
		shouldBuf := status < 300

		if shouldBuf {
			// store the header before the body, so we can efficiently
			// and conveniently use a single buffer for both; gob
			// decoder will only read up to end of gob message, and
			// the rest will be the body, which will be written
			// implicitly for us by the recorder
			err := gob.NewEncoder(buf).Encode(headerAndStatus{
				Header: header,
				Status: status,
			})
			if err != nil {
				log.Printf("[ERROR] Encoding headers for cache entry: %v; not caching this request", err)
				return false
			}
		}

		return shouldBuf
	})

	// execute next handlers in chain
	err := combo.next.ServeHTTP(rr, combo.req)
	if err != nil {
		return err
	}

	// if response body was not buffered, response was
	// already written and we are unable to cache
	if !rr.Buffered() {
		return errUncacheable
	}

	// add to cache
	dest.SetBytes(buf.Bytes())

	return nil
}

type headerAndStatus struct {
	Header http.Header
	Status int
}

type getterContext struct {
	rw   http.ResponseWriter
	req  *http.Request
	next caddyhttp.Handler
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var (
	pool   *groupcache.HTTPPool
	poolMu sync.Mutex
)

var errUncacheable = fmt.Errorf("uncacheable")

const groupName = "http_requests"

// Interface guards
var (
	_ caddy.Provisioner           = (*Cache)(nil)
	_ caddy.Validator             = (*Cache)(nil)
	_ caddyhttp.MiddlewareHandler = (*Cache)(nil)
)
