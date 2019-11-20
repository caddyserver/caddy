package tcp

import (
	"bufio"
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

	p := Proxy{Addr: ":3001"}

	port := ":3000"
	ch2 := make(chan net.Conn)
	go simpleListener(port, ch2) // proxy

	t.Run("simple proxy", func(t *testing.T) {
		client, _ := net.Dial("tcp", "localhost"+port)
		src := <-ch2

		go p.Proxy(caddy.Context{}, src, bufio.NewReader(nil))

		data := []byte("hello, world")
		nWrite, _ := client.Write(data)
		upstream := <-ch
		read := make([]byte, len(data))
		nRead, _ := upstream.Read(read)
		if nWrite != nRead || string(data) != string(read) {
			t.Error("read not match send")
		}
		data = []byte("caddy proxy")
		nWrite, _ = upstream.Write(data)

		nRead, _ = client.Read(read)
		if nWrite != nRead {
			t.Error("read not match send")
		}
	})
}
