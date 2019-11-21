package tcp

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyproxy"
)

func (Proxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "proxy.target.tcp",
		New:  func() caddy.Module { return new(Proxy) },
	}
}

var (
	_ caddy.Module       = (*Proxy)(nil)
	_ caddyproxy.Proxier = (*Proxy)(nil)
)

type Proxy struct {
	Addr string `json:"addr,omitempty"`

	ProxyProtocolVersion int `json:"proxy_protocol_version,omitempty"`

	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (p *Proxy) Proxy(ctx caddy.Context, dst net.Conn, src net.Conn) error {
	if err := p.sendProxyHeader(dst, src); err != nil {
		return err
	}
	errors := make(chan error, 1)
	go exchange(dst, src, errors)
	go exchange(src, dst, errors)

	return <-errors
}

func exchange(dst net.Conn, src net.Conn, errors chan error) {
	_, err := io.Copy(dst, src)
	errors <- err
}

func (p *Proxy) sendProxyHeader(w io.Writer, src net.Conn) error {
	switch p.ProxyProtocolVersion {
	case 0:
		return nil
	case 1:
		var srcAddr, dstAddr *net.TCPAddr
		if a, ok := src.RemoteAddr().(*net.TCPAddr); ok {
			srcAddr = a
		}
		if a, ok := src.LocalAddr().(*net.TCPAddr); ok {
			dstAddr = a
		}

		if srcAddr == nil || dstAddr == nil {
			_, err := io.WriteString(w, "PROXY UNKNOWN\r\n")
			return err
		}

		family := "TCP4"
		if srcAddr.IP.To4() == nil {
			family = "TCP6"
		}
		_, err := fmt.Fprintf(w, "PROXY %s %s %d %s %d\r\n", family, srcAddr.IP, srcAddr.Port, dstAddr.IP, dstAddr.Port)
		return err
	default:
		return fmt.Errorf("PROXY protocol version %d not supported", p.ProxyProtocolVersion)
	}
}

func (p *Proxy) dial() (net.Conn, error) {
	conn, err := net.Dial("tcp", p.Addr)
	return conn, err
}

func (p *Proxy) Dial(ctx caddy.Context) (net.Conn, error) {
	if p.DialContext != nil {
		return p.DialContext(ctx, "tcp", p.Addr)
	}
	return p.dial()
}
