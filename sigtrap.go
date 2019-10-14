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

package caddy

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/caddyserver/caddy/telemetry"
)

// TrapSignals create signal handlers for all applicable signals for this
// system. If your Go program uses signals, this is a rather invasive
// function; best to implement them yourself in that case. Signals are not
// required for the caddy package to function properly, but this is a
// convenient way to allow the user to control this part of your program.
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
				for _, f := range OnProcessExit {
					f() // important cleanup actions only
				}
				os.Exit(2)
			}

			log.Println("[INFO] SIGINT: Shutting down")

			telemetry.AppendUnique("sigtrap", "SIGINT")
			go telemetry.StopEmitting() // not guaranteed to finish in time; that's OK (just don't block!)

			// important cleanup actions before shutdown callbacks
			for _, f := range OnProcessExit {
				f()
			}

			go func() {
				os.Exit(executeShutdownCallbacks("SIGINT"))
			}()
		}
	}()
}

// executeShutdownCallbacks executes the shutdown callbacks as initiated
// by signame. It logs any errors and returns the recommended exit status.
// This function is idempotent; subsequent invocations always return 0.
func executeShutdownCallbacks(signame string) (exitCode int) {
	shutdownCallbacksOnce.Do(func() {
		// execute third-party shutdown hooks
		EmitEvent(ShutdownEvent, signame)

		errs := allShutdownCallbacks()
		if len(errs) > 0 {
			for _, err := range errs {
				log.Printf("[ERROR] %s shutdown: %v", signame, err)
			}
			exitCode = 4
		}
	})
	return
}

// allShutdownCallbacks executes all the shutdown callbacks
// for all the instances, and returns all the errors generated
// during their execution. An error executing one shutdown
// callback does not stop execution of others. Only one shutdown
// callback is executed at a time.
func allShutdownCallbacks() []error {
	var errs []error
	instancesMu.Lock()
	for _, inst := range instances {
		errs = append(errs, inst.ShutdownCallbacks()...)
	}
	instancesMu.Unlock()
	return errs
}

// shutdownCallbacksOnce ensures that shutdown callbacks
// for all instances are only executed once.
var shutdownCallbacksOnce sync.Once
