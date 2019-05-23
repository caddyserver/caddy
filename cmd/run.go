package caddycmd

import (
	"log"

	"bitbucket.org/lightcodelabs/caddy2"
)

// Main executes the main function of the caddy command.
func Main() {
	addr := ":1234" // TODO: for dev only
	err := caddy2.StartAdmin(addr)
	if err != nil {
		log.Fatal(err)
	}
	defer caddy2.StopAdmin()

	log.Println("Caddy 2 admin endpoint listening on", addr)

	select {}
}
