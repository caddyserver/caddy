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

var (
	statusMu sync.Mutex

	// globalStatus store windows service status, it can be
	// use to notify caddy status.
	globalStatus chan<- svc.Status

	// pendingStatus is the most recent status requested while
	// no channel was set; SetGlobalStatus delivers it.
	pendingStatus *svc.Status
)

// SetGlobalStatus assigns the channel through which status updates
// will be sent to the SCM. This is typically provided by the service
// handler when the service starts. A status requested before the
// channel was set (for example Ready, when the config finished
// loading before the SCM invoked the service handler) is sent now,
// so that the service does not remain in START_PENDING.
//
// The lock is held across that send: it makes registration and replay
// atomic with respect to send, so a status requested concurrently
// cannot reach the SCM ahead of the replayed one. Blocking on the send
// while holding the lock is safe because the channel is drained by the
// service handler, which never calls back into this package.
func SetGlobalStatus(status chan<- svc.Status) {
	statusMu.Lock()
	defer statusMu.Unlock()

	globalStatus = status
	pending := pendingStatus
	pendingStatus = nil

	if status != nil && pending != nil {
		status <- *pending
	}
}

// send delivers status to the SCM, or remembers it until
// SetGlobalStatus provides the channel. Statuses are delivered in the
// order they were requested; see SetGlobalStatus for why the lock is
// held across the send.
func send(status svc.Status) {
	statusMu.Lock()
	defer statusMu.Unlock()

	if globalStatus == nil {
		pendingStatus = &status
		return
	}
	globalStatus <- status
}

// Ready notifies the SCM that the service is fully running and ready
// to accept stop or shutdown control requests.
func Ready() error {
	send(svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	})
	return nil
}

// Reloading notifies the SCM that the service is entering a transitional
// state.
func Reloading() error {
	send(svc.Status{State: svc.StartPending})
	return nil
}

// Stopping notifies the SCM that the service is in the process of stopping.
// This allows Windows to track the shutdown transition properly.
func Stopping() error {
	send(svc.Status{State: svc.StopPending})
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

	send(svc.Status{State: state, Accepts: accepts})
	return nil
}

// Error notifies the SCM that the service is stopping due to a failure,
// including a service-specific exit code.
func Error(err error, code int) error {
	send(svc.Status{
		State:                   svc.StopPending,
		ServiceSpecificExitCode: uint32(code),
	})
	return nil
}
