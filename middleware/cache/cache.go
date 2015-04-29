// Package cache provides a simple middleware layer that remembers
// previously served requests and serves those from memory.
package cache

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mholt/caddy/middleware"
)

// Example line in CaddyFile: cache 60 128mb 10mb

// Cache is an http.Handler that can remembers and sends back stored responses
type Cache struct {
	Next     middleware.Handler
	Lifetime int
	Entries  map[string]CacheEntry // url -> entry
	Rule     Rule
}

type CacheEntry struct {
	created   int64
	lastUsed  int64
	Size      int //bytes
	Code      int
	HeaderMap http.Header
	Body      []byte
}

type Rule struct {
	MaxAge            int64 //seconds
	MaxCacheSize      int64 //bytes
	MaxCacheEntrySize int   //bytes
}

// New creates a new cache middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	rules, err := parse(c)
	if err != nil {
		return nil, err
	}
	return func(next middleware.Handler) middleware.Handler {
		// TODO: handle more than one rule? handle first or last rule?
		return Cache{Next: next, Lifetime: 60 * 10, Entries: make(map[string]CacheEntry), Rule: rules[0]}
	}, nil
}

func parse(c middleware.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {

		var ageString, cacheSizeString, cacheEntrySizeString string
		if !c.Args(&ageString, &cacheSizeString, &cacheEntrySizeString) {
			return rules, c.ArgErr()
		}
		age, err := strconv.Atoi(ageString)
		if err != nil {
			return rules, c.ArgErr()
		}
		cacheSize, err := humanize.ParseBytes(cacheSizeString)
		if err != nil {
			return rules, c.ArgErr()
		}
		cacheEntrySize, err := humanize.ParseBytes(cacheEntrySizeString)
		if err != nil {
			return rules, c.ArgErr()
		}
		rule := Rule{MaxAge: int64(age), MaxCacheSize: int64(cacheSize), MaxCacheEntrySize: int(cacheEntrySize)}
		rules = append(rules, rule)
	}

	return rules, nil
}

// Writes the headers and body to the writer
func WriteEntry(w http.ResponseWriter, entry CacheEntry) {
	w.WriteHeader(entry.Code)
	for key, valueArray := range entry.HeaderMap {
		for _, value := range valueArray {
			w.Header().Set(key, value)
		}
	}
	w.Write(entry.Body)
}

func ClientAllowsCaching(r *http.Request) bool {
	// TODO: Actually parse the Cache-Control and Pragma header
	// Currently this won't do any caching if these headers are present
	return r.Header.Get("Cache-Control") == "" && r.Header.Get("Pragma") == ""
}

func ServerAllowsCaching(headers http.Header) bool {
	// TODO: This is more strict than necessary. Better parsing needed.
	cacheControl := headers.Get("Cache-Control")
	return cacheControl == "" || cacheControl == "public"
}

// ServeHTTP serves a gzipped response if the client supports it.
func (c Cache) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if r.Method == "GET" {
		key := r.RequestURI
		now := time.Now().Unix()
		entry, inCache := c.Entries[key]

		if inCache && now-entry.created < c.Rule.MaxAge && ClientAllowsCaching(r) {
			entry.lastUsed = time.Now().Unix()
		} else {
			record := httptest.NewRecorder()
			status, err := c.Next.ServeHTTP(record, r)
			normalResponse := err == nil && status < 300 && record.Code < 300

			body := record.Body.Bytes()
			bodySize := len(body) + 100 // TODO: Better approximation of size of headers, etc. For now just 100 bytes.
			entry = CacheEntry{created: now, lastUsed: now, Code: record.Code, HeaderMap: record.HeaderMap, Body: body, Size: bodySize}

			if normalResponse && bodySize < c.Rule.MaxCacheEntrySize && ServerAllowsCaching(record.Header()) {
				// adds response to cache
				c.Entries[key] = entry
			}
		}

		WriteEntry(w, entry)
		return entry.Code, nil
	} else {
		// skip caching entirely
		return c.Next.ServeHTTP(w, r)
	}

}
