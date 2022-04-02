package caddyhttp

import (
	"context"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

// RequestContext is a fast context.Context implementation
// which allows for fast lookups and stores in the context of
// an http.Request. It is not safe to be setting and getting
// values to/from it from different goroutines, however
// such problem should not arise since requests are usually handled
// by a single goroutine/worker.
type RequestContext struct {
	context.Context
	values         map[interface{}]interface{}
	extendLifespan bool
}

// GetValue looks up a value specifically in this RequestContext,
// without looking it up in the parent context if not found.
// This should usually only be used on the known context keys:
// ReplacerCtxKey, ServerCtxKey, OriginalRequestCtxKey, VarsCtxKey, ErrorCtxKey.
func (c *RequestContext) GetValue(key interface{}) interface{} {
	if value, ok := c.values[key]; ok {
		return value
	} else if key == requestContextKey {
		return c
	}
	return nil
}

// SetValue sets a value in the fast RequestContext map.
func (c *RequestContext) SetValue(key interface{}, value interface{}) {
	c.values[key] = value
}

// Value looks up a value by key stored in the context.
// It searches through the RequestContext first, and then
// looks the value up in the parent context.
func (c *RequestContext) Value(key interface{}) interface{} {
	if value := c.GetValue(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

// Return returns the request context. Using a RequestContext after calling
// Return is prone to race conditions, since internally the context gets
// returned to a sync.Pool. This means that Return should only be called
// AFTER any handlers using the request have returned.
func (c *RequestContext) Return() {
	if c.extendLifespan {
		// don't return to the global pool if it needs to be kept alive
		return
	}

	c.Context = nil

	// only store the vars map to keep it allocated as well
	// this and the next map clear should be fast and won't resize the map
	varMap := c.values[VarsCtxKey].(map[string]interface{})
	for key := range varMap {
		delete(varMap, key)
	}

	for key := range c.values {
		delete(c.values, key)
	}
	c.values[VarsCtxKey] = varMap

	requestContextPool.Put(c)
}

// RequestContextValue looks up a value in the given http.Request
// and short-circuits in the RequestContext map stored in the request's
// context. Thus it should, like GetValue, be used only on known keys.
func RequestContextValue(r *http.Request, key interface{}) interface{} {
	c := r.Context().Value(requestContextKey).(*RequestContext)
	return c.GetValue(key)
}

// RequestContextSetValue sets a value in the given http.Request's RequestContext map.
func RequestContextSetValue(r *http.Request, key interface{}, value interface{}) {
	c := r.Context().Value(requestContextKey).(*RequestContext)
	c.SetValue(key, value)
}

// RequestContextExtendLifespan extends the RequestContext's lifespan by marking
// it as non-returnable and not actually returning it to the pool during Return.
// This allows the request and its context to be safely passed to external packages
// where the request context's lifespan isn't known, i.e. it might be used after the request is handled.
func RequestContextExtendLifespan(r *http.Request) {
	c := r.Context().Value(requestContextKey).(*RequestContext)
	c.extendLifespan = true
}

// NewRequestContext initializes and returns a new RequestContext which can
// then be added to an http request using request.WithContext. Internally
// this uses a pool of RequestContext, so always make sure to call
// rctx.Return after you're done using the context.
func NewRequestContext() *RequestContext {
	return requestContextPool.Get().(*RequestContext)
}

type requestContextKeyT struct{}

var requestContextKey = requestContextKeyT{}

var requestContextPool = sync.Pool{
	New: func() interface{} {
		// initialize the map, so that all of the buckets
		// are allocated and keys stored
		return &RequestContext{
			values: map[interface{}]interface{}{
				caddy.ReplacerCtxKey:  nil,
				ServerCtxKey:          nil,
				VarsCtxKey:            make(map[string]interface{}),
				OriginalRequestCtxKey: nil,
			},
		}
	},
}
