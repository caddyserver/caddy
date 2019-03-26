package main

import (
	"log"

	"bitbucket.org/lightcodelabs/caddy2"

	// this is where modules get plugged in
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
	_ "bitbucket.org/lightcodelabs/dynamicconfig"
)

func main() {
	err := caddy2.Start("127.0.0.1:1234")
	if err != nil {
		log.Fatal(err)
	}
	defer caddy2.Stop()

	select {}
}
