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

package caddy

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/caddyserver/caddy/v2/notify"
)

// Run can load the config and call notify.Ready before the SCM invokes
// the service handler. The handler must then report StartPending followed
// by Running, not leave the service in START_PENDING.
func TestServiceHandlerReportsRunningWhenReadyCameFirst(t *testing.T) {
	notify.SetGlobalStatus(nil)
	t.Cleanup(func() { notify.SetGlobalStatus(nil) })

	if err := notify.Ready(); err != nil {
		t.Fatal(err)
	}

	requests := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 4)
	// Execute blocks on requests until the SCM asks it to stop; a stop
	// would exit the test process, so the goroutine is left waiting.
	go runner{}.Execute(nil, requests, status)

	want := []svc.State{svc.StartPending, svc.Running}
	for _, state := range want {
		select {
		case got := <-status:
			if got.State != state {
				t.Fatalf("state = %v, want %v", got.State, state)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %v status was reported", state)
		}
	}

	// the handler still answers control requests afterwards
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: current}
	select {
	case got := <-status:
		if got != current {
			t.Fatalf("interrogate answered %+v, want %+v", got, current)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrogate was not answered")
	}
}
