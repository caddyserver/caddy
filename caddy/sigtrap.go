package caddy

import (
	"log"
	"os"
	"os/signal"

	"github.com/mholt/caddy/server"
)

func init() {
	// Trap quit signals (cross-platform)
	go func() {
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, os.Interrupt, os.Kill)
		<-shutdown

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
	}()
}
