// Package middleware includes a variety of middleware for
// the servers to use, according to their configuration.
package middleware

import (
	"net/http"
	"strings"
)

// This init function registers middleware. Register middleware
// in the order they should be executed during a request.
// Middlewares execute in an order like A-B-C-C-B-A.
func init() {
	register("gzip", Gzip)
	register("header", Headers)
	register("log", RequestLog)
	register("rewrite", Rewrite)
	register("redir", Redirect)
	register("ext", Extensionless)
}

type (
	// Generator represents the outer layer of a middleware that
	// parses tokens to configure the middleware instance.
	Generator func(parser) Middleware

	// Middleware is the middle layer which represents the traditional
	// idea of middleware: it is passed the next HandlerFunc in the chain
	// and returns the inner layer, which is the actual HandlerFunc.
	Middleware func(http.HandlerFunc) http.HandlerFunc

	// parser is the type which middleware generators use to access
	// tokens and other information they need to configure the instance.
	parser interface {
		Next() bool
		NextArg() bool
		NextLine() bool
		Val() string
		OpenCurlyBrace() bool
		CloseCurlyBrace() bool
		ArgErr() Middleware
		Err(string, string) Middleware
		Args(...*string)
		Startup(func() error)
		Root() string
		Host() string
		Port() string
	}
)

var (
	// registry stores the registered middleware:
	// both the order and the directives to which they
	// are bound.
	registry = struct {
		directiveMap map[string]Generator
		order        []string
	}{
		directiveMap: make(map[string]Generator),
	}
)

// GetGenerator gets the generator function (outer layer)
// of a middleware, according to the directive passed in.
func GetGenerator(directive string) (Generator, bool) {
	rm, ok := registry.directiveMap[directive]
	return rm, ok
}

// register binds a middleware generator (outer function)
// to a directive. Upon each request, middleware will be
// executed in the order they are registered.
func register(directive string, generator Generator) {
	registry.directiveMap[directive] = generator
	registry.order = append(registry.order, directive)
}

// Ordered returns the ordered list of registered directives.
func Ordered() []string {
	return registry.order
}

// Registered returns whether or not a directive is registered.
func Registered(directive string) bool {
	_, ok := GetGenerator(directive)
	return ok
}

// Path represents a URI path, maybe with pattern characters.
type Path string

// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily matched.
func (p Path) Matches(other string) bool {
	return strings.HasPrefix(string(p), other)
}
