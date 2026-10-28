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

package notify

import (
	"log"
	"strings"
	"sync"

	"golang.org/x/sys/windows/svc"
)

// statusMu guards the service status below. It is held while sending
// to globalStatus so that every update reaches the SCM in order. The
// receiver is the dispatcher loop in golang.org/x/sys/windows/svc,
// which always accepts status updates and never takes this lock.
var statusMu sync.Mutex

var (
	// globalStatus store windows service status, it can be
	// use to notify caddy status.
	globalStatus chan<- svc.Status

	// currentStatus is the authoritative service status. It is kept
	// while no channel is attached, so a status reported before the
	// service handler starts is not lost.
	currentStatus = svc.Status{State: svc.StartPending}

	// stopping is set once shutdown begins; after that, only stop
	// states are accepted.
	stopping bool
)

// SetGlobalStatus assigns the channel through which status updates
// will be sent to the SCM and publishes the current status to it.
// Passing nil detaches the channel and resets the status, which the
// service handler does before it returns.
func SetGlobalStatus(status chan<- svc.Status) {
	statusMu.Lock()
	defer statusMu.Unlock()
	globalStatus = status
	if status == nil {
		currentStatus = svc.Status{State: svc.StartPending}
		stopping = false
		return
	}
	status <- currentStatus
}

// Interrogate republishes the current status, in response to the
// SCM's Interrogate control request.
func Interrogate() {
	statusMu.Lock()
	defer statusMu.Unlock()
	if globalStatus != nil {
		globalStatus <- currentStatus
	}
}

// setStatus makes s the current status and publishes it if a channel
// is attached. Once shutdown has begun, statuses other than StopPending
// and Stopped are ignored, so a late Ready cannot undo it.
func setStatus(s svc.Status) {
	statusMu.Lock()
	defer statusMu.Unlock()
	setStatusLocked(s)
}

func setStatusLocked(s svc.Status) {
	if stopping && s.State != svc.StopPending && s.State != svc.Stopped {
		return
	}
	currentStatus = s
	if globalStatus != nil {
		globalStatus <- s
	}
}

// Ready notifies the SCM that the service is fully running and ready
// to accept stop or shutdown control requests.
func Ready() error {
	setStatus(svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	})
	return nil
}

// Reloading notifies the SCM that the service is entering a transitional
// state.
func Reloading() error {
	setStatus(svc.Status{State: svc.StartPending})
	return nil
}

// Stopping notifies the SCM that the service is in the process of stopping.
// This allows Windows to track the shutdown transition properly.
func Stopping() error {
	statusMu.Lock()
	defer statusMu.Unlock()
	stopping = true
	setStatusLocked(svc.Status{State: svc.StopPending})
	return nil
}

// Status sends an arbitrary service state to the SCM based on a string
// identifier of [svc.State].
// The unknown states will be logged.
func Status(name string) error {
	var state svc.State
	var accepts svc.Accepted
	accepts = 0

	switch strings.ToLower(name) {
	case "stopped":
		state = svc.Stopped
	case "start_pending":
		state = svc.StartPending
	case "stop_pending":
		state = svc.StopPending
	case "running":
		state = svc.Running
		accepts = svc.AcceptStop | svc.AcceptShutdown
	case "continue_pending":
		state = svc.ContinuePending
	case "pause_pending":
		state = svc.PausePending
	case "paused":
		state = svc.Paused
		accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	default:
		log.Printf("unknown state: %s", name)
		return nil
	}

	setStatus(svc.Status{State: state, Accepts: accepts})
	return nil
}

// Error notifies the SCM that the service is stopping due to a failure,
// including a service-specific exit code.
func Error(err error, code int) error {
	setStatus(svc.Status{
		State:                   svc.StopPending,
		ServiceSpecificExitCode: uint32(code),
	})
	return nil
}
