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
	// statusMu serializes access to globalStatus and pendingStatus,
	// and is held while sending so updates reach the SCM in order.
	// The receiver (the svc package's dispatcher loop) never takes
	// this lock, so holding it during the send cannot deadlock.
	statusMu sync.Mutex

	// globalStatus store windows service status, it can be
	// use to notify caddy status.
	globalStatus chan<- svc.Status

	// pendingStatus is the latest status reported before
	// globalStatus was attached, if any.
	pendingStatus *svc.Status
)

// SetGlobalStatus assigns the channel through which status updates
// will be sent to the SCM. This is typically provided by the service
// handler when the service starts.
//
// Caddy may finish loading its config before the service handler
// starts, so SetGlobalStatus publishes the latest status reported
// before attachment, or StartPending if there was none. Passing nil
// detaches the channel and discards any retained status.
func SetGlobalStatus(status chan<- svc.Status) {
	statusMu.Lock()
	defer statusMu.Unlock()
	globalStatus = status
	initial := svc.Status{State: svc.StartPending}
	if pendingStatus != nil {
		initial = *pendingStatus
		pendingStatus = nil
	}
	if status != nil {
		status <- initial
	}
}

// send publishes s to the SCM, or retains it for SetGlobalStatus
// if no channel is attached yet.
func send(s svc.Status) {
	statusMu.Lock()
	defer statusMu.Unlock()
	if globalStatus == nil {
		pendingStatus = &s
		return
	}
	globalStatus <- s
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
