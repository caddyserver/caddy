package main

import (
	"log"

	_ "net/http/pprof"

	"bitbucket.org/lightcodelabs/caddy2"

	// this is where modules get plugged in

	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/caddylog"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/staticfiles"
	_ "bitbucket.org/lightcodelabs/dynamicconfig"
	_ "bitbucket.org/lightcodelabs/proxy"
)

func main() {
	err := caddy2.StartAdmin("127.0.0.1:1234")
	if err != nil {
		log.Fatal(err)
	}
	defer caddy2.StopAdmin()

	select {}
}
