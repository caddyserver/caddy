// Package app holds application-global state to make it accessible
// by other packages in the application.
//
// This package differs from config in that the things in app aren't
// really related to server configuration.
package app

import (
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/mholt/caddy/server"
)

const (
	// Name is the program name
	Name = "Caddy"

	// Version is the program version
	Version = "0.7.5"
)

var (
	// Servers is a list of all the currently-listening servers
	Servers []*server.Server

	// ServersMutex protects the Servers slice during changes
	ServersMutex sync.Mutex

	// Wg is used to wait for all servers to shut down
	Wg sync.WaitGroup

	// Http2 indicates whether HTTP2 is enabled or not
	Http2 bool // TODO: temporary flag until http2 is standard

	// Quiet mode hides non-error initialization output
	Quiet bool
)

// SetCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
func SetCPU(cpu string) error {
	var numCPU int

	availCPU := runtime.NumCPU()

	if strings.HasSuffix(cpu, "%") {
		// Percent
		var percent float32
		pctStr := cpu[:len(cpu)-1]
		pctInt, err := strconv.Atoi(pctStr)
		if err != nil || pctInt < 1 || pctInt > 100 {
			return errors.New("invalid CPU value: percentage must be between 1-100")
		}
		percent = float32(pctInt) / 100
		numCPU = int(float32(availCPU) * percent)
	} else {
		// Number
		num, err := strconv.Atoi(cpu)
		if err != nil || num < 1 {
			return errors.New("invalid CPU value: provide a number or percent greater than 0")
		}
		numCPU = num
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	runtime.GOMAXPROCS(numCPU)
	return nil
}
