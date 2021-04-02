// Copyright 2015 Matthew Holt and The Caddy Authors
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
	"os"
	"os/signal"
	"syscall"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// trapSignalsPosix captures POSIX-only signals.
func trapSignalsPosix() {
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)

		for sig := range sigchan {
			switch sig {
			case syscall.SIGQUIT:
				Log().Info("quitting process immediately", zap.String("signal", "SIGQUIT"))
				certmagic.CleanUpOwnLocks(Log()) // try to clean up locks anyway, it's important
				os.Exit(ExitCodeForceQuit)

			case syscall.SIGTERM:
				Log().Info("shutting down apps, then terminating", zap.String("signal", "SIGTERM"))
				exitProcessFromSignal("SIGTERM")

			case syscall.SIGUSR1:
				Log().Info("not implemented", zap.String("signal", "SIGUSR1"))

			case syscall.SIGUSR2:
				Log().Info("not implemented", zap.String("signal", "SIGUSR2"))

			case syscall.SIGHUP:
				// ignore; this signal is sometimes sent outside of the user's control
				Log().Info("not implemented", zap.String("signal", "SIGHUP"))
			}
		}
	}()
}
