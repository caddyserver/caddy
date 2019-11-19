package udp

import (
	"bufio"
	"net"

	"github.com/caddyserver/caddy/v2"
)

type Proxy struct {
}

func (p *Proxy) Proxy(ctx caddy.Context, conn net.Conn, buf *bufio.Reader) {
	panic("not implement")
}
