package caddy

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/mholt/caddy/server"
)

func init() {
	// Trap interrupt signal (cross-platform); triggers forceful shutdown
	// that executes shutdown callbacks first. A second interrupt signal
	// will exit the process immediately.
	go func() {
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, os.Interrupt)

		for i := 0; true; i++ {
			<-shutdown

			if i > 0 {
				log.Println("[INFO] SIGINT: Force quit")
				os.Exit(1)
			}

			log.Println("[INFO] SIGINT: Shutting down")
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
