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
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func await(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("status operation did not return")
	}
}

func checkStatus(t *testing.T, statuses <-chan svc.Status, want svc.Status) {
	t.Helper()
	select {
	case got := <-statuses:
		if got != want {
			t.Fatalf("status: got %+v, want %+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("status was not published")
	}
}

func TestStatusOwner(t *testing.T) {
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for _, tc := range []struct {
		name    string
		prepare func()
		want    svc.Status
	}{
		{"initial", func() {}, svc.Status{State: svc.StartPending}},
		{"ready", func() { _ = Reloading(); _ = Ready() }, running},
		{"error", func() { _ = Ready(); _ = Error(nil, 7) }, svc.Status{State: svc.StopPending, ServiceSpecificExitCode: 7}},
		{"explicit", func() { _ = Status("paused") }, svc.Status{State: svc.Paused, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue}},
		{"stopping", func() { _ = Stopping(); _ = Ready(); _ = Reloading() }, svc.Status{State: svc.StopPending}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetGlobalStatus(nil)
			t.Cleanup(func() { SetGlobalStatus(nil) })
			statuses := make(chan svc.Status, 2)
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.prepare() // No attached channel: must return without a receiver.
				SetGlobalStatus(statuses)
				Interrogate()
			}()
			await(t, done)
			checkStatus(t, statuses, tc.want)
			checkStatus(t, statuses, tc.want)
		})
	}
}

func TestStatusOrderWithUnbufferedReceiver(t *testing.T) {
	SetGlobalStatus(nil)
	statuses := make(chan svc.Status)
	done := make(chan struct{})
	go func() {
		defer close(done)
		SetGlobalStatus(statuses)
		_ = Ready()
		_ = Reloading()
		_ = Error(nil, 3)
		_ = Ready() // A reload error is not an irreversible shutdown.
		_ = Stopping()
		_ = Ready()
		_ = Status("running")
		_ = Status("stopped")
		Interrogate()
	}()
	// Drain on assertion failure so a blocked sender can release statusMu.
	t.Cleanup(func() {
		for {
			select {
			case <-statuses:
			case <-done:
				SetGlobalStatus(nil)
				return
			case <-time.After(5 * time.Second):
				t.Error("sender did not finish during cleanup")
				return
			}
		}
	})
	for _, want := range []svc.Status{
		{State: svc.StartPending},
		{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown},
		{State: svc.StartPending},
		{State: svc.StopPending, ServiceSpecificExitCode: 3},
		{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown},
		{State: svc.StopPending}, {State: svc.Stopped}, {State: svc.Stopped},
	} {
		checkStatus(t, statuses, want)
	}
	await(t, done)
}
