// +build !windows

package caddy

import (
	"bytes"
	"errors"
	"log"
	"net"
	"path/filepath"

	"github.com/mholt/caddy/caddy/https"
)

// Restart restarts the entire application; gracefully with zero
// downtime if on a POSIX-compatible system, or forcefully if on
// Windows but with imperceptibly-short downtime.
//
// The behavior can be controlled by the RestartMode variable,
// where "inproc" will restart forcefully in process same as
// Windows on a POSIX-compatible system.
//
// The restarted application will use newCaddyfile as its input
// configuration. If newCaddyfile is nil, the current (existing)
// Caddyfile configuration will be used.
//
// Note: The process must exist in the same place on the disk in
// order for this to work. Thus, multiple graceful restarts don't
// work if executing with `go run`, since the binary is cleaned up
// when `go run` sees the initial parent process exit.
func Restart(newCaddyfile Input) error {
	log.Println("[INFO] Restarting")

	if newCaddyfile == nil {
		caddyfileMu.Lock()
		newCaddyfile = caddyfile
		caddyfileMu.Unlock()
	}

	// Get certificates for any new hosts in the new Caddyfile without causing downtime
	err := getCertsForNewCaddyfile(newCaddyfile)
	if err != nil {
		return errors.New("TLS preload: " + err.Error())
	}

	// Add file descriptors of all the sockets for new instance
	serversMu.Lock()
	for _, s := range servers {
		restartFds[s.Addr] = s.ListenerFd()
	}
	serversMu.Unlock()

	return restartInProc(newCaddyfile)
}

func getCertsForNewCaddyfile(newCaddyfile Input) error {
	// parse the new caddyfile only up to (and including) TLS
	// so we can know what we need to get certs for.
	configs, _, _, err := loadConfigsUpToIncludingTLS(filepath.Base(newCaddyfile.Path()), bytes.NewReader(newCaddyfile.Body()))
	if err != nil {
		return errors.New("loading Caddyfile: " + err.Error())
	}

	// first mark the configs that are qualified for managed TLS
	https.MarkQualified(configs)

	// since we group by bind address to obtain certs, we must call
	// EnableTLS to make sure the port is set properly first
	// (can ignore error since we aren't actually using the certs)
	https.EnableTLS(configs, false)

	// find out if we can let the acme package start its own challenge listener
	// on port 80
	var proxyACME bool
	serversMu.Lock()
	for _, s := range servers {
		_, port, _ := net.SplitHostPort(s.Addr)
		if port == "80" {
			proxyACME = true
			break
		}
	}
	serversMu.Unlock()

	// place certs on the disk
	err = https.ObtainCerts(configs, false, proxyACME)
	if err != nil {
		return errors.New("obtaining certs: " + err.Error())
	}

	return nil
}
