package caddycmd

import (
	"log"

	"bitbucket.org/lightcodelabs/caddy2"
)

// Main executes the main function of the caddy command.
func Main() {
	err := caddy2.StartAdmin("127.0.0.1:1234")
	if err != nil {
		log.Fatal(err)
	}
	defer caddy2.StopAdmin()

	select {}
}
