package caddy

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/mholt/caddy/caddy/letsencrypt"
	"github.com/mholt/caddy/server"
)

func init() {
	letsencrypt.OnRenew = func() error { return Restart(nil) }

	// Trap signals
	go func() {
		shutdown, reload := make(chan os.Signal, 1), make(chan os.Signal, 1)
		signal.Notify(shutdown, os.Interrupt, os.Kill) // quit the process
		signal.Notify(reload, syscall.SIGUSR1)         // reload configuration

		for {
			select {
			case <-shutdown:
				var exitCode int

				serversMu.Lock()
				errs := server.ShutdownCallbacks(servers)
				serversMu.Unlock()
				if len(errs) > 0 {
					for _, err := range errs {
						log.Println(err)
					}
					exitCode = 1
				}
				os.Exit(exitCode)

			case <-reload:
				err := Restart(nil)
				if err != nil {
					log.Println(err)
				}
			}
		}
	}()
}

// isLocalhost returns true if the string looks explicitly like a localhost address.
func isLocalhost(s string) bool {
	return s == "localhost" || s == "::1" || strings.HasPrefix(s, "127.")
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
