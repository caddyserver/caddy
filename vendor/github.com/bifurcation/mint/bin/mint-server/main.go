package main

import (
	"crypto/x509"
	"flag"
	"log"
	"net"

	"github.com/bifurcation/mint"
)

var port string

func main() {
	var config mint.Config
	config.SendSessionTickets = true
	config.ServerName = "localhost"
	priv, cert, err := mint.MakeNewSelfSignedCert("localhost", mint.RSA_PKCS1_SHA256)
	config.Certificates = []*mint.Certificate{
		{
			Chain:      []*x509.Certificate{cert},
			PrivateKey: priv,
		},
	}
	config.Init(false)

	flag.StringVar(&port, "port", "4430", "port")
	flag.Parse()

	service := "0.0.0.0:" + port
	listener, err := mint.Listen("tcp", service, &config)

	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 10)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}

		n, err = conn.Write([]byte("hello world"))
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
		break
	}
	log.Println("server: conn: closed")
}
