package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/server"
)

var (
	conf  string
	http2 bool // TODO: temporary flag until http2 is standard
	quiet bool
	cpu   string
)

func init() {
	flag.StringVar(&conf, "conf", config.DefaultConfigFile, "The configuration file to use")
	flag.BoolVar(&http2, "http2", true, "Enable HTTP/2 support") // TODO: temporary flag until http2 merged into std lib
	flag.BoolVar(&quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&config.Root, "root", config.DefaultRoot, "Root path to default site")
	flag.StringVar(&config.Host, "host", config.DefaultHost, "Default host")
	flag.StringVar(&config.Port, "port", config.DefaultPort, "Default port")
	flag.Parse()
}

func main() {
	var wg sync.WaitGroup

	// Set CPU cap
	err := setCPU(cpu)
	if err != nil {
		log.Fatal(err)
	}

	// Load config from file
	allConfigs, err := loadConfigs(conf)
	if err != nil {
		log.Fatal(err)
	}

	// Group by address (virtual hosts)
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
				log.Fatal(err) // kill whole process to avoid a half-alive zombie server
			}
		}(s)

		if !quiet {
			for _, config := range configs {
				fmt.Println(config.Address())
			}
		}
	}

	wg.Wait()
}

// loadConfigs loads configuration from a file.
func loadConfigs(confPath string) ([]server.Config, error) {
	var allConfigs []server.Config

	file, err := os.Open(confPath)
	if err == nil {
		defer file.Close()
		allConfigs, err = config.Load(path.Base(confPath), file)
		if err != nil {
			return allConfigs, err
		}
	} else {
		if os.IsNotExist(err) {
			// This is only a problem if the user
			// explicitly specified a config file
			if confPath != config.DefaultConfigFile {
				return allConfigs, err
			}
		} else {
			// ... but anything else is always a problem
			return allConfigs, err
		}
	}

	// If config file was empty or didn't exist, use default
	if len(allConfigs) == 0 {
		allConfigs = []server.Config{config.Default()}
	}

	return allConfigs, nil
}

// arrangeBindings groups configurations by their bind address. For example,
// a server that should listen on localhost and another on 127.0.0.1 will
// be grouped into the same address: 127.0.0.1. It will return an error
// if the address lookup fails or if a TLS listener is configured on the
// same address as a plaintext HTTP listener.
func arrangeBindings(allConfigs []server.Config) (map[string][]server.Config, error) {
	addresses := make(map[string][]server.Config)

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

// setCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
func setCPU(cpu string) error {
	var numCPU int

	availCPU := runtime.NumCPU()

	if strings.HasSuffix(cpu, "%") {
		// Percent
		var percent float32
		pctStr := cpu[:len(cpu)-1]
		pctInt, err := strconv.Atoi(pctStr)
		if err != nil || pctInt < 1 || pctInt > 100 {
			return errors.New("Invalid CPU value: percentage must be between 1-100")
		}
		percent = float32(pctInt) / 100
		numCPU = int(float32(availCPU) * percent)
	} else {
		// Number
		num, err := strconv.Atoi(cpu)
		if err != nil || num < 1 {
			return errors.New("Invalid CPU value: provide a number or percent greater than 0")
		}
		numCPU = num
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	runtime.GOMAXPROCS(numCPU)
	return nil
}
