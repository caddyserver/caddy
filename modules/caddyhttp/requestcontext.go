package caddyhttp

import (
	"context"
	"net/http"
)

// RequestContext is a fast context.Context implementation
// which allows for fast lookups and stores in the context of
// an http.Request. It is not safe to be setting and getting
// values to/from it from different goroutines, however
// such problem should not arise since requests are usually handled
// by a single goroutine/worker.
type RequestContext struct {
	context.Context
	// We store the map as a slice to use less space
	// (storing structs of key,value has an overhead of 16 bytes/pair,
	//  and storing a map[] has an even bigger overhead)
	// and speed up the allocation of a RequestContext (again due to the size)
	values []interface{}
}

// GetValue looks up a value specifically in this RequestContext,
// without looking it up in the parent context if not found.
// This should usually only be used on the known context keys:
// ReplacerCtxKey, ServerCtxKey, OriginalRequestCtxKey, VarsCtxKey, ErrorCtxKey.
func (c *RequestContext) GetValue(key interface{}) interface{} {
	for i := 0; i < len(c.values); i += 2 {
		if c.values[i] == key {
			return c.values[i+1]
		}
	}
	if key == requestContextKey {
		return c
	}
	return nil
}

// SetValue sets a value in the fast RequestContext map.
func (c *RequestContext) SetValue(key interface{}, value interface{}) {
	c.values = append(c.values, key, value)
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

// RequestContextValue looks up a value in the given http.Request
// and short-circuits in the RequestContext map stored in the request's
// context. Thus it should, like GetValue, be used only on known keys.
func RequestContextValue(r *http.Request, key interface{}) interface{} {
	c := r.Context().Value(requestContextKey).(*RequestContext)
	return c.GetValue(key)
}

// RequestContextValue sets a value in the given http.Request's RequestContext map.
func RequestContextSetValue(r *http.Request, key interface{}, value interface{}) {
	c := r.Context().Value(requestContextKey).(*RequestContext)
	c.SetValue(key, value)
}

type requestContextKeyT struct{}

var requestContextKey = requestContextKeyT{}
