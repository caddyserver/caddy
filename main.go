package main

import (
	"flag"
	"log"
	"sync"

	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/server"
)

var conf string

func init() {
	flag.StringVar(&conf, "conf", server.DefaultConfigFile, "the configuration file to use")
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
