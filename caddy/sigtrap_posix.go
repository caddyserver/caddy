// +build !windows

package caddy

import (
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
			err := Restart(nil)
			if err != nil {
				log.Println(err)
			}
		}
	}()
}
