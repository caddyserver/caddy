package main

import (
	"log"
	"sync"

	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/server"
)

func main() {
	var wg sync.WaitGroup

	vhosts, err := config.Load("Caddyfile")
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
		wg.Add(1)
		go func(s *server.Server) {
			defer wg.Done()
			err := s.Serve()
			if err != nil {
				s.Log(err)
			}
		}(s)
	}

	wg.Wait()
}
