package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/mholt/caddy/app"
	"github.com/mholt/caddy/config"
	"github.com/mholt/caddy/server"
)

var (
	conf    string
	cpu     string
	version bool
)

func init() {
	flag.StringVar(&conf, "conf", "", "Configuration file to use (default="+config.DefaultConfigFile+")")
	flag.BoolVar(&app.Http2, "http2", true, "Enable HTTP/2 support") // TODO: temporary flag until http2 merged into std lib
	flag.BoolVar(&app.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&config.Root, "root", config.DefaultRoot, "Root path to default site")
	flag.StringVar(&config.Host, "host", config.DefaultHost, "Default host")
	flag.StringVar(&config.Port, "port", config.DefaultPort, "Default port")
	flag.BoolVar(&version, "version", false, "Show version")
}

func main() {
	flag.Parse()

	if version {
		fmt.Printf("%s %s\n", app.Name, app.Version)
		os.Exit(0)
	}

	// Set CPU cap
	err := app.SetCPU(cpu)
	if err != nil {
		log.Fatal(err)
	}

	// Load address configurations from highest priority input
	addresses, err := loadConfigs()
	if err != nil {
		log.Fatal(err)
	}

	// Start each server with its one or more configurations
	for addr, configs := range addresses {
		s, err := server.New(addr.String(), configs)
		if err != nil {
			log.Fatal(err)
		}
		s.HTTP2 = app.Http2 // TODO: This setting is temporary
		app.Wg.Add(1)
		go func(s *server.Server) {
			defer app.Wg.Done()
			err := s.Serve()
			if err != nil {
				log.Fatal(err) // kill whole process to avoid a half-alive zombie server
			}
		}(s)

		app.Servers = append(app.Servers, s)
	}

	// Show initialization output
	if !app.Quiet {
		var checkedFdLimit bool
		for addr, configs := range addresses {
			for _, conf := range configs {
				// Print address of site
				fmt.Println(conf.Address())

				// Note if non-localhost site resolves to loopback interface
				if addr.IP.IsLoopback() && !isLocalhost(conf.Host) {
					fmt.Printf("Notice: %s is only accessible on this machine (%s)\n",
						conf.Host, addr.IP.String())
				}
				if !checkedFdLimit && !addr.IP.IsLoopback() && !isLocalhost(conf.Host) {
					checkFdlimit()
					checkedFdLimit = true
				}
			}
		}
	}

	// Wait for all listeners to stop
	app.Wg.Wait()
}

// checkFdlimit issues a warning if the OS max file descriptors is below a recommended minimum.
func checkFdlimit() {
	const min = 4096

	// Warn if ulimit is too low for production sites
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		out, err := exec.Command("sh", "-c", "ulimit -n").Output() // use sh because ulimit isn't in Linux $PATH
		if err == nil {
			// Note that an error here need not be reported
			lim, err := strconv.Atoi(string(bytes.TrimSpace(out)))
			if err == nil && lim < min {
				fmt.Printf("Warning: File descriptor limit %d is too low for production sites. At least %d is recommended. Set with \"ulimit -n %d\".\n", lim, min, min)
			}
		}
	}
}

// isLocalhost returns true if the string looks explicitly like a localhost address.
func isLocalhost(s string) bool {
	return s == "localhost" || s == "::1" || strings.HasPrefix(s, "127.")
}

// loadConfigs loads configuration from a file or stdin (piped).
// The configurations are grouped by bind address.
// Configuration is obtained from one of three sources, tried
// in this order: 1. -conf flag, 2. stdin, 3. Caddyfile.
// If none of those are available, a default configuration is
// loaded.
func loadConfigs() (config.Group, error) {
	// -conf flag
	if conf != "" {
		file, err := os.Open(conf)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return config.Load(path.Base(conf), file)
	}

	// stdin
	fi, err := os.Stdin.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		// Note that a non-nil error is not a problem. Windows
		// will not create a stdin if there is no pipe, which
		// produces an error when calling Stat(). But Unix will
		// make one either way, which is why we also check that
		// bitmask.
		confBody, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		if len(confBody) > 0 {
			return config.Load("stdin", bytes.NewReader(confBody))
		}
	}

	// Caddyfile
	file, err := os.Open(config.DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return config.Default()
		}
		return nil, err
	}
	defer file.Close()

	return config.Load(config.DefaultConfigFile, file)
}
