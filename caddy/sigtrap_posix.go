// +build !windows

package caddy

import (
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	// Trap POSIX-only signals
	go func() {
		reload := make(chan os.Signal, 1)
		signal.Notify(reload, syscall.SIGUSR1) // reload configuration

		for {
			<-reload

			var updatedCaddyfile Input

			caddyfileMu.Lock()
			if caddyfile == nil {
				// Hmm, did spawing process forget to close stdin? Anyhow, this is unusual.
				log.Println("[ERROR] SIGUSR1: no caddyfile to reload")
				caddyfileMu.Unlock()
				continue
			}
			if caddyfile.IsFile() {
				body, err := ioutil.ReadFile(caddyfile.Path())
				if err == nil {
					caddyfile = CaddyfileInput{
						Filepath: caddyfile.Path(),
						Contents: body,
						RealFile: true,
					}
				}
			}
			caddyfileMu.Unlock()

			err := Restart(updatedCaddyfile)
			if err != nil {
				log.Println("error at restart:", err)
			}
		}
	}()
}
