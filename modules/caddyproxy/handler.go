package caddyproxy

import (
	"bufio"
	"net"

	"github.com/caddyserver/caddy/v2"
)

// Handler is the interface to handle the connection, just like the http handler.
// After reading from connection, handler should write any thing that want to be proxied
// into the buffer otherwise it can't be proxied correctly
type Handler interface {
	Handle(ctx caddy.Context, conn net.Conn, buf *bufio.Writer) error
}

// HandleFunc is the function to handle data before it sending to dest
type HandleFunc func(ctx caddy.Context, conn net.Conn, buf *bufio.Writer) error

// Handle implements the Handler interface
func (f HandleFunc) Handle(ctx caddy.Context, conn net.Conn, buf *bufio.Writer) error {
	return f(ctx, conn, buf)
}
