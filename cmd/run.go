package caddycmd

import (
	"flag"
	"log"

	"github.com/caddyserver/caddy"
)

// Main executes the main function of the caddy command.
func Main() {
	flag.Parse()

	err := caddy.StartAdmin(*listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer caddy.StopAdmin()

	log.Println("Caddy 2 admin endpoint listening on", *listenAddr)

	select {}
}

// TODO: for dev only
var listenAddr = flag.String("listen", ":1234", "The admin endpoint listener address")
