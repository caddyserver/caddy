// +build !windows

package caddy

import (
	"io/ioutil"
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

				var updatedCaddyfile Input

				caddyfileMu.Lock()
				if caddyfile == nil {
					// Hmm, did spawing process forget to close stdin? Anyhow, this is unusual.
					log.Println("[ERROR] SIGUSR1: no Caddyfile to reload (was stdin left open?)")
					caddyfileMu.Unlock()
					continue
				}
				if caddyfile.IsFile() {
					body, err := ioutil.ReadFile(caddyfile.Path())
					if err == nil {
						updatedCaddyfile = CaddyfileInput{
							Filepath: caddyfile.Path(),
							Contents: body,
							RealFile: true,
						}
					}
				}
				caddyfileMu.Unlock()

				err := Restart(updatedCaddyfile)
				if err != nil {
					log.Printf("[ERROR] SIGUSR1: %v", err)
				}
			}
		}
	}()
}
