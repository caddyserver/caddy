package udp

import (
	bufio2 "bufio"
	"net"

	"github.com/caddyserver/caddy/v2"
)

type Proxy struct {
	dst net.Conn
	src net.Conn
}

func (p *Proxy) Proxy(ctx caddy.Context, src net.Conn, buf *bufio2.Reader) error {
	panic("not implement")
	return nil
}
