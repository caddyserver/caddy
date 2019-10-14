// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !windows,!plan9,!nacl,!js

package caddy

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/caddyserver/caddy/telemetry"
)

// trapSignalsPosix captures POSIX-only signals.
func trapSignalsPosix() {
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)

		for sig := range sigchan {
			switch sig {
			case syscall.SIGQUIT:
				log.Println("[INFO] SIGQUIT: Quitting process immediately")
				for _, f := range OnProcessExit {
					f() // only perform important cleanup actions
				}
				os.Exit(0)

			case syscall.SIGTERM:
				log.Println("[INFO] SIGTERM: Shutting down servers then terminating")
				exitCode := executeShutdownCallbacks("SIGTERM")
				for _, f := range OnProcessExit {
					f() // only perform important cleanup actions
				}
				err := Stop()
				if err != nil {
					log.Printf("[ERROR] SIGTERM stop: %v", err)
					exitCode = 3
				}

				telemetry.AppendUnique("sigtrap", "SIGTERM")
				go telemetry.StopEmitting() // won't finish in time, but that's OK - just don't block

				os.Exit(exitCode)

			case syscall.SIGUSR1:
				log.Println("[INFO] SIGUSR1: Reloading")
				go telemetry.AppendUnique("sigtrap", "SIGUSR1")

				// Start with the existing Caddyfile
				caddyfileToUse, inst, err := getCurrentCaddyfile()
				if err != nil {
					log.Printf("[ERROR] SIGUSR1: %v", err)
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
					caddyfileToUse = newCaddyfile
				}

				// Backup old event hooks
				oldEventHooks := cloneEventHooks()

				// Purge the old event hooks
				purgeEventHooks()

				// Kick off the restart; our work is done
				EmitEvent(InstanceRestartEvent, nil)
				_, err = inst.Restart(caddyfileToUse)
				if err != nil {
					restoreEventHooks(oldEventHooks)

					log.Printf("[ERROR] SIGUSR1: %v", err)
				}

			case syscall.SIGUSR2:
				log.Println("[INFO] SIGUSR2: Upgrading")
				go telemetry.AppendUnique("sigtrap", "SIGUSR2")
				if err := Upgrade(); err != nil {
					log.Printf("[ERROR] SIGUSR2: upgrading: %v", err)
				}

			case syscall.SIGHUP:
				// ignore; this signal is sometimes sent outside of the user's control
				go telemetry.AppendUnique("sigtrap", "SIGHUP")
			}
		}
	}()
}
