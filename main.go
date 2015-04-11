package main

import (
	"flag"
	"log"
	"sync"

	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/server"
)

var (
	conf  string
	http2 bool
)

func init() {
	flag.StringVar(&conf, "conf", server.DefaultConfigFile, "the configuration file to use")
	flag.BoolVar(&http2, "http2", true, "enable HTTP/2 support") // temporary flag until http2 merged into std lib
}

func main() {
	var wg sync.WaitGroup

	flag.Parse()

	vhosts, err := config.Load(conf)
	if err != nil {
		if config.IsNotFound(err) {
			vhosts = config.Default()
		} else {
			log.Fatal(err)
		}
	}

	for _, conf := range vhosts {
		s, err := server.New(conf)
		if err != nil {
			log.Fatal(err)
		}
		s.HTTP2 = http2 // TODO: This setting is temporary
		wg.Add(1)
		go func(s *server.Server) {
			defer wg.Done()
			err := s.Serve()
			if err != nil {
				log.Println(err)
			}
		}(s)
	}

	wg.Wait()
}
