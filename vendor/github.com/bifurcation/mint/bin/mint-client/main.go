package main

import (
	"flag"
	"fmt"

	"github.com/bifurcation/mint"
)

var addr string
var dtls bool
var dontValidate bool

func main() {
	c := mint.Config{}

	flag.StringVar(&addr, "addr", "localhost:4430", "port")
	flag.BoolVar(&dtls, "dtls", false, "use DTLS")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.Parse()
	if dontValidate {
		c.InsecureSkipVerify = true
	}
	network := "tcp"
	if dtls {
		network = "udp"
	}
	conn, err := mint.Dial(network, addr, &c)

	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	request := "GET / HTTP/1.0\r\n\r\n"
	conn.Write([]byte(request))

	response := ""
	buffer := make([]byte, 1024)
	var read int
	for err == nil {
		read, err = conn.Read(buffer)
		fmt.Println(" ~~ read: ", read)
		response += string(buffer)
	}
	fmt.Println("err:", err)
	fmt.Println("Received from server:")
	fmt.Println(response)
}
