// +build !windows

package caddy

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// trapSignalsPosix captures POSIX-only signals.
func trapSignalsPosix() {
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1)

		for sig := range sigchan {
			switch sig {
			case syscall.SIGTERM:
				log.Println("[INFO] SIGTERM: Terminating process")
				if PidFile != "" {
					os.Remove(PidFile)
				}
				os.Exit(0)

			case syscall.SIGQUIT:
				log.Println("[INFO] SIGQUIT: Shutting down")
				exitCode := executeShutdownCallbacks("SIGQUIT")
				err := Stop()
				if err != nil {
					log.Printf("[ERROR] SIGQUIT stop: %v", err)
					exitCode = 1
				}
				if PidFile != "" {
					os.Remove(PidFile)
				}
				os.Exit(exitCode)

			case syscall.SIGHUP:
				log.Println("[INFO] SIGHUP: Hanging up")
				err := Stop()
				if err != nil {
					log.Printf("[ERROR] SIGHUP stop: %v", err)
				}

			case syscall.SIGUSR1:
				log.Println("[INFO] SIGUSR1: Reloading")

				// Start with the existing Caddyfile
				instancesMu.Lock()
				if len(instances) == 0 {
					instancesMu.Unlock()
					log.Println("[ERROR] SIGUSR1: No server instances are fully running")
					continue
				}
				inst := instances[0] // we only support one instance at this time
				instancesMu.Unlock()

				updatedCaddyfile := inst.caddyfileInput
				if updatedCaddyfile == nil {
					// Hmm, did spawing process forget to close stdin? Anyhow, this is unusual.
					log.Println("[ERROR] SIGUSR1: no Caddyfile to reload (was stdin left open?)")
					continue
				}
				if loaderUsed.loader == nil {
					// This also should never happen
					log.Println("[ERROR] SIGUSR1: no Caddyfile loader with which to reload Caddyfile")
					continue
				}

				// Load the updated Caddyfile
				newCaddyfile, err := loaderUsed.loader.Load(inst.serverType)
				if err != nil {
					log.Printf("[ERROR] SIGUSR1: loading updated Caddyfile: %v", err)
					continue
				}
				if newCaddyfile != nil {
					updatedCaddyfile = newCaddyfile
				}

				// Kick off the restart; our work is done
				inst, err = inst.Restart(updatedCaddyfile)
				if err != nil {
					log.Printf("[ERROR] SIGUSR1: %v", err)
				}
			}
		}
	}()
}
