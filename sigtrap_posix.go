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

//go:build !windows && !plan9 && !nacl && !js

package caddy

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// trapSignalsPosix captures POSIX-only signals.
func trapSignalsPosix() {
	// Ignore all SIGPIPE signals to prevent weird issues with systemd: https://github.com/dunglas/frankenphp/issues/1020
	// Docker/Moby has a similar hack: https://github.com/moby/moby/blob/d828b032a87606ae34267e349bf7f7ccb1f6495a/cmd/dockerd/docker.go#L87-L90
	signal.Ignore(syscall.SIGPIPE)

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)

		for sig := range sigchan {
			switch sig {
			case syscall.SIGQUIT:
				Log().Info("quitting process immediately", zap.String("signal", "SIGQUIT"))
				certmagic.CleanUpOwnLocks(context.TODO(), Log()) // try to clean up locks anyway, it's important
				os.Exit(ExitCodeForceQuit)

			case syscall.SIGTERM:
				Log().Info("shutting down apps, then terminating", zap.String("signal", "SIGTERM"))
				exitProcessFromSignal("SIGTERM")

			case syscall.SIGUSR1:
				// If we know the last source config file/adapter (set when starting
				// via `caddy run --config <file> --adapter <adapter>`), attempt
				// to reload from that source. Otherwise, ignore the signal.
				file, adapter := getLastConfig()
				if file == "" {
					Log().Info("last config unknown, ignored SIGUSR1",
						zap.String("signal", "SIGUSR1"))
					break
				}
				Log().Info("reloading config from last-known source",
					zap.String("signal", "SIGUSR1"),
					zap.String("file", file),
					zap.String("adapter", adapter))
				if err := ReloadFromSource(file, adapter); errors.Is(err, errReloadFromSourceUnavailable) {
					// No reload helper available (likely not started via caddy run).
					Log().Warn("reload from source unavailable in this process; ignored SIGUSR1",
						zap.String("file", file),
						zap.String("adapter", adapter))
				} else if err != nil {
					Log().Error("failed to reload config from file",
						zap.Error(err),
						zap.String("file", file),
						zap.String("adapter", adapter))
				} else {
					Log().Info("successfully reloaded config from file",
						zap.String("file", file),
						zap.String("adapter", adapter))
				}

			case syscall.SIGUSR2:
				Log().Info("not implemented", zap.String("signal", "SIGUSR2"))

			case syscall.SIGHUP:
				// ignore; this signal is sometimes sent outside of the user's control
				Log().Info("not implemented", zap.String("signal", "SIGHUP"))
			}
		}
	}()
}
