package caddy

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/mholt/caddy/server"
)

// TrapSignals create signal handlers for all applicable signals for this
// system. If your Go program uses signals, this is a rather invasive
// function; best to implement them yourself in that case. Signals are not
// required for the caddy package to function properly, but this is a
// convenient way to allow the user to control this package of your program.
func TrapSignals() {
	trapSignalsCrossPlatform()
	trapSignalsPosix()
}

// trapSignalsCrossPlatform captures SIGINT, which triggers forceful
// shutdown that executes shutdown callbacks first. A second interrupt
// signal will exit the process immediately.
func trapSignalsCrossPlatform() {
	go func() {
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, os.Interrupt)

		for i := 0; true; i++ {
			<-shutdown

			if i > 0 {
				log.Println("[INFO] SIGINT: Force quit")
				if PidFile != "" {
					os.Remove(PidFile)
				}
				os.Exit(1)
			}

			log.Println("[INFO] SIGINT: Shutting down")

			if PidFile != "" {
				os.Remove(PidFile)
			}

			go os.Exit(executeShutdownCallbacks("SIGINT"))
		}
	}()
}

// executeShutdownCallbacks executes the shutdown callbacks as initiated
// by signame. It logs any errors and returns the recommended exit status.
// This function is idempotent; subsequent invocations always return 0.
func executeShutdownCallbacks(signame string) (exitCode int) {
	shutdownCallbacksOnce.Do(func() {
		serversMu.Lock()
		errs := server.ShutdownCallbacks(servers)
		serversMu.Unlock()

		if len(errs) > 0 {
			for _, err := range errs {
				log.Printf("[ERROR] %s shutdown: %v", signame, err)
			}
			exitCode = 1
		}
	})
	return
}

var shutdownCallbacksOnce sync.Once
