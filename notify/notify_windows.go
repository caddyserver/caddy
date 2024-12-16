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

import "golang.org/x/sys/windows/svc"

// globalStatus store windows service status, it can be
// use to notify caddy status.
var globalStatus chan<- svc.Status

func SetGlobalStatus(status chan<- svc.Status) {
	globalStatus = status
}

func Ready() error {
	if globalStatus != nil {
		globalStatus <- svc.Status{
			State:   svc.Running,
			Accepts: svc.AcceptStop | svc.AcceptShutdown,
		}
	}
	return nil
}

func Reloading() error {
	if globalStatus != nil {
		globalStatus <- svc.Status{State: svc.StartPending}
	}
	return nil
}

func Stopping() error {
	if globalStatus != nil {
		globalStatus <- svc.Status{State: svc.StopPending}
	}
	return nil
}

// TODO: not implemented
func Status(_ string) error { return nil }

// TODO: not implemented
func Error(_ error, _ int) error { return nil }
