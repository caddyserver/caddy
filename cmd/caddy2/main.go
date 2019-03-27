package main

import (
	"log"

	"bitbucket.org/lightcodelabs/caddy2"

	_ "net/http/pprof"

	// this is where modules get plugged in
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
	_ "bitbucket.org/lightcodelabs/dynamicconfig"
)

func main() {
	err := caddy2.StartAdmin("127.0.0.1:1234")
	if err != nil {
		log.Fatal(err)
	}
	defer caddy2.StopAdmin()

	select {}
}
