package caddyhttp

import (
	"context"
)

type contextEntry struct {
	k, v interface{}
}

type mapContext struct {
	context.Context
	values []contextEntry
}

func (c *mapContext) Value(key interface{}) interface{} {
	for i, v := range c.values {
		if v.k == key {
			return c.values[i].v
		}
	}
	if key == mapContextKey {
		return c
	}
	return c.Context.Value(key)
}

func mapContextSetValues(ctx context.Context, values ...contextEntry) {
	c := ctx.Value(mapContextKey).(*mapContext)
	c.values = append(c.values, values...)
}

type mapContextKeyT struct{}

var mapContextKey = mapContextKeyT{}
