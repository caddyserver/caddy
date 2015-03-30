// Package middleware provides some types and functions common among middleware.
package middleware

import "net/http"

type (
	// Generator represents the outer layer of a middleware that
	// parses tokens to configure the middleware instance.
	Generator func(Controller) (Middleware, error)

	// Middleware is the middle layer which represents the traditional
	// idea of middleware: it is passed the next HandlerFunc in the chain
	// and returns the inner layer, which is the actual Handler.
	Middleware func(HandlerFunc) HandlerFunc

	// HandlerFunc is like http.HandlerFunc except it returns a status code
	// and an error. It is the inner-most layer which serves individual
	// requests. The status code is for the client's benefit; the error
	// value is for the server's benefit. The status code will be sent to
	// the client while the error value will be logged privately. Sometimes,
	// an error status code (4xx or 5xx) may be returned with a nil error
	// when there is no reason to log the error on the server.
	//
	// If a HandlerFunc returns an error (status >= 400), it should NOT
	// write to the response. This philosophy makes middleware.HandlerFunc
	// different from http.HandlerFunc: error handling should happen at
	// the application layer or in dedicated error-handling middleware
	// only, rather than with an "every middleware for itself" paradigm.
	//
	// The application or error-handling middleware should incorporate logic
	// to ensure that the client always gets a proper response according to
	// the status code. For security reasons, it should probably not reveal
	// the actual error message. (Instead it should be logged, for example.)
	//
	// Handlers which do write to the response should return a status value
	// < 400 as a signal that a response has been written. In other words,
	// only error-handling middleware or the application will write to the
	// response for a status code >= 400. When ANY handler writes to the
	// response, it should return a status code < 400 to signal others to
	// NOT write to the response again, which would be erroneous.
	HandlerFunc func(http.ResponseWriter, *http.Request) (int, error)

	// Handler is like http.Handler except ServeHTTP returns a status code
	// and an error. See HandlerFunc documentation for more information.
	Handler interface {
		ServeHTTP(http.ResponseWriter, *http.Request) (int, error)
	}

	// A Controller provides access to properties of the server. Middleware
	// generators use a Controller to construct their instances.
	Controller interface {
		Dispenser

		// Startup registers a function to execute when the server starts.
		Startup(func() error)

		// Shutdown registers a function to execute when the server exits.
		Shutdown(func() error)

		// Root returns the file path from which the server is serving.
		Root() string

		// Host returns the hostname the server is bound to.
		Host() string

		// Port returns the port that the server is listening on.
		Port() string

		// Context returns the path scope that the Controller is in.
		// Note: This is not currently used, but may be in the future.
		Context() Path
	}

	// A Dispenser provides structured access to tokens from a configuration
	// file. It dispenses tokens to middleware for parsing so that middleware
	// can configure themselves.
	Dispenser interface {
		// Next loads the next token. Returns true if a token
		// was loaded; false otherwise. If false, all tokens
		// have already been consumed.
		Next() bool

		// NextArg loads the next token if it is on the same
		// line. Returns true if a token was loaded; false
		// otherwise. If false, all tokens on the line have
		// been consumed.
		NextArg() bool

		// NextLine loads the next token only if it is NOT on the same
		// line as the current token, and returns true if a token was
		// loaded; false otherwise. If false, there is not another token
		// or it is on the same line.
		NextLine() bool

		// NextBlock can be used as the condition of a for loop
		// to load the next token as long as it opens a block or
		// is already in a block. It returns true if a token was
		// loaded, or false when the block's closing curly brace
		// was loaded and thus the block ended. Nested blocks are
		// not (currently) supported.
		NextBlock() bool

		// Val gets the text of the current token.
		Val() string

		// Args is a convenience function that loads the next arguments
		// (tokens on the same line) into an arbitrary number of strings
		// pointed to in arguments. If there are fewer tokens available
		// than string pointers, the remaining strings will not be changed
		// and false will be returned. If there were enough tokens available
		// to fill the arguments, then true will be returned.
		Args(...*string) bool

		// RemainingArgs loads any more arguments (tokens on the same line)
		// into a slice and returns them. Open curly brace tokens also indicate
		// the end of arguments, and the curly brace is not included in
		// the return value nor is it loaded.
		RemainingArgs() []string

		// ArgErr returns an argument error, meaning that another
		// argument was expected but not found. In other words,
		// a line break, EOF, or open curly brace was encountered instead of
		// an argument.
		ArgErr() error

		// Err generates a custom parse error with a message of msg.
		Err(string) error
	}
)
