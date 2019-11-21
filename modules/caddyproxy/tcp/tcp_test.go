package tcp

import (
	"io"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func simpleListener(addr string, ch chan net.Conn) {
	ln, _ := net.Listen("tcp", addr)
	for {
		conn, _ := ln.Accept()
		ch <- conn
	}
}

func TestProxy_Proxy(t *testing.T) {
	ch := make(chan net.Conn)
	go simpleListener(":3001", ch) // upstream

	p := Proxy{Addr: ":3001", ProxyProtocolVersion: 1}

	port := ":3000"
	ch2 := make(chan net.Conn)
	go simpleListener(port, ch2) // proxy

	t.Run("simple proxy", func(t *testing.T) {
		client, _ := net.Dial("tcp", "localhost"+port)
		src := <-ch2

		dst, _ := p.Dial(caddy.Context{})

		go p.Proxy(caddy.Context{}, dst, src)
		upstream := <-ch

		proxyHeader := []byte("PROXY TCP4 127.0.0.1 52734 127.0.0.1 3000\r\n")
		read := readFrom(upstream)

		if len(proxyHeader) != len(read) || string(read[:5]) != "PROXY" {
			t.Logf("read: %s, len: %d", string(read), len(read))
			t.Error("read proxy header error")
		}

		data := []byte("hello, world")
		nWrite, _ := client.Write(data)
		read = readFrom(upstream)

		if nWrite != len(read) || string(data) != string(read) {
			t.Logf("read: %s, write: %s", string(read), string(data))
			t.Error("read not match send")
		}
		data = []byte("caddy proxy")
		nWrite, _ = upstream.Write(data)

		read = readFrom(client)
		if nWrite != len(read) {
			t.Logf("read: %s, write: %s", string(read), string(data))
			t.Error("read not match send")
		}
	})
}
func readFrom(r io.Reader) []byte {
	buf := make([]byte, 100000)
	n, _ := r.Read(buf)
	return buf[:n]
}
