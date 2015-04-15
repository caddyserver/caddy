package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/server"
)

var (
	conf  string
	http2 bool
)

func init() {
	flag.StringVar(&conf, "conf", config.DefaultConfigFile, "the configuration file to use")
	flag.BoolVar(&http2, "http2", true, "enable HTTP/2 support") // temporary flag until http2 merged into std lib
}

func main() {
	var wg sync.WaitGroup

	flag.Parse()

	// Load config from file
	allConfigs, err := config.Load(conf)
	if err != nil {
		if config.IsNotFound(err) {
			allConfigs = config.Default()
		} else {
			log.Fatal(err)
		}
	}

	// Group by address (virtual hosting)
	addresses, err := arrangeBindings(allConfigs)
	if err != nil {
		log.Fatal(err)
	}

	// Start each server with its one or more configurations
	for addr, configs := range addresses {
		s, err := server.New(addr, configs, configs[0].TLS.Enabled)
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

// arrangeBindings groups configurations by their bind address. For example,
// a server that should listen on localhost and another on 127.0.0.1 will
// be grouped into the same address: 127.0.0.1. It will return an error
// if the address lookup fails or if a TLS listener is configured on the
// same address as a plaintext HTTP listener.
func arrangeBindings(allConfigs []config.Config) (map[string][]config.Config, error) {
	addresses := make(map[string][]config.Config)

	// Group configs by bind address
	for _, conf := range allConfigs {
		addr, err := net.ResolveTCPAddr("tcp", conf.Address())
		if err != nil {
			return addresses, err
		}
		addresses[addr.String()] = append(addresses[addr.String()], conf)
	}

	// Don't allow HTTP and HTTPS to be served on the same address
	for _, configs := range addresses {
		isTLS := configs[0].TLS.Enabled
		for _, config := range configs {
			if config.TLS.Enabled != isTLS {
				thisConfigProto, otherConfigProto := "HTTP", "HTTP"
				if config.TLS.Enabled {
					thisConfigProto = "HTTPS"
				}
				if configs[0].TLS.Enabled {
					otherConfigProto = "HTTPS"
				}
				return addresses, fmt.Errorf("Configuration error: Cannot multiplex %s (%s) and %s (%s) on same address",
					configs[0].Address(), otherConfigProto, config.Address(), thisConfigProto)
			}
		}
	}

	return addresses, nil
}
