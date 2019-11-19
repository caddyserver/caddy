package tcp

import (
	"bufio"
	"net"

	"github.com/caddyserver/caddy/v2"
)

type Proxy struct {
	src net.Conn
	dst net.Conn
}

func (p *Proxy) Proxy(ctx caddy.Context, conn net.Conn, buf *bufio.Reader) {
	panic("not implement")
}
