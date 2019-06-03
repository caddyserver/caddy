package caddycmd

import (
	"flag"
	"log"

	"bitbucket.org/lightcodelabs/caddy2"
)

// Main executes the main function of the caddy command.
func Main() {
	flag.Parse()

	err := caddy2.StartAdmin(*listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer caddy2.StopAdmin()

	log.Println("Caddy 2 admin endpoint listening on", *listenAddr)

	select {}
}

// TODO: for dev only
var listenAddr = flag.String("listen", ":1234", "The admin endpoint listener address")
