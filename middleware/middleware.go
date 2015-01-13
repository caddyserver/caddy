// Package middleware includes a variety of middleware for
// the servers to use, according to their configuration.
package middleware

import "net/http"

// Middleware is a type of function that generates a new
// layer of middleware. It is imperative that the HandlerFunc
// being passed in is executed by the middleware, otherwise
// part of the stack will not be called.
type Middleware func(http.HandlerFunc) http.HandlerFunc
