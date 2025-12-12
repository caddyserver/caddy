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

	"golang.org/x/sys/windows/svc"
)

// globalStatus store windows service status, it can be
// use to notify caddy status.
var globalStatus chan<- svc.Status

// SetGlobalStatus assigns the channel through which status updates
// will be sent to the SCM. This is typically provided by the service
// handler when the service starts.
func SetGlobalStatus(status chan<- svc.Status) {
	globalStatus = status
}

// Ready notifies the SCM that the service is fully running and ready
// to accept stop or shutdown control requests.
func Ready() error {
	if globalStatus != nil {
		globalStatus <- svc.Status{
			State:   svc.Running,
			Accepts: svc.AcceptStop | svc.AcceptShutdown,
		}
	}
	return nil
}

// Reloading notifies the SCM that the service is entering a transitional
// state.
func Reloading() error {
	if globalStatus != nil {
		globalStatus <- svc.Status{State: svc.StartPending}
	}
	return nil
}

// Stopping notifies the SCM that the service is in the process of stopping.
// This allows Windows to track the shutdown transition properly.
func Stopping() error {
	if globalStatus != nil {
		globalStatus <- svc.Status{State: svc.StopPending}
	}
	return nil
}

// Status sends an arbitrary service state to the SCM based on a string
// identifier of [svc.State].
// The unknown states will be logged.
func Status(name string) error {
	if globalStatus == nil {
		return nil
	}

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

	globalStatus <- svc.Status{State: state, Accepts: accepts}
	return nil
}

// Error notifies the SCM that the service is stopping due to a failure,
// including a service-specific exit code.
func Error(err error, code int) error {
	if globalStatus != nil {
		globalStatus <- svc.Status{
			State:                   svc.StopPending,
			ServiceSpecificExitCode: uint32(code),
		}
	}

	return nil
}
