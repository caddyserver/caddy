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
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/notify"
	"golang.org/x/sys/windows/svc"
)

func TestRunnerStatusOrdering(t *testing.T) {
	for _, order := range []string{"ready first", "runner first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			notify.SetGlobalStatus(nil)
			t.Cleanup(func() { notify.SetGlobalStatus(nil) })
			requests := make(chan svc.ChangeRequest)
			statuses := make(chan svc.Status, 4)
			done := make(chan struct{})
			if order == "ready first" {
				_ = notify.Ready()
			}
			go func() {
				defer close(done)
				runner{}.Execute(nil, requests, statuses)
			}()
			if order == "runner first" {
				select {
				case s := <-statuses:
					if s.State != svc.StartPending {
						t.Fatalf("initial status: %+v", s)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("runner did not start")
				}
			}
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				defer close(requests)
				if order != "ready first" {
					_ = notify.Ready()
				}
				// The snapshot is deliberately stale: the owner must publish RUNNING.
				requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.StartPending}}
			}()
			t.Cleanup(func() {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("runner did not return")
				}
			})
			select {
			case <-requestDone:
			case <-time.After(5 * time.Second):
				t.Fatal("notification or Interrogate blocked")
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("runner did not return")
			}
			close(statuses)
			want := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			var last svc.Status
			ready := false
			for s := range statuses {
				ready = ready || s == want
				if ready && s != want {
					t.Fatalf("stale status after RUNNING: %+v", s)
				}
				last = s
			}
			if last != want {
				t.Fatalf("last status: got %+v, want %+v", last, want)
			}
			returned := make(chan struct{})
			go func() { _ = notify.Ready(); close(returned) }()
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("Ready blocked after runner returned")
			}
		})
	}
}

func TestRunnerStopRacesReady(t *testing.T) {
	const envKey = "CADDY_TEST_SERVICE_CONTROL"
	controls := map[string]svc.Cmd{"stop": svc.Stop, "shutdown": svc.Shutdown}
	if name := os.Getenv(envKey); name != "" {
		requests := make(chan svc.ChangeRequest)
		statuses := make(chan svc.Status)
		go runner{}.Execute(nil, requests, statuses)
		go func() {
			for s := range statuses {
				fmt.Println(s.State)
			}
		}()
		go func() {
			for {
				_ = notify.Ready()
			}
		}()
		requests <- svc.ChangeRequest{Cmd: controls[name]}
		time.Sleep(10 * time.Second)
		os.Exit(5) // Stop/Shutdown must exit the process before this fallback.
	}
	for name := range controls {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunnerStopRacesReady$", "-test.count=1")
			child.Env = append(os.Environ(), envKey+"="+name)
			out, err := child.Output()
			if err != nil {
				t.Fatalf("child failed: %v; output:\n%s", err, out)
			}
			stopping := false
			for line := range strings.FieldsSeq(string(out)) {
				stopping = stopping || line == fmt.Sprint(svc.StopPending)
				if stopping && line == fmt.Sprint(svc.Running) {
					t.Fatalf("RUNNING after STOP_PENDING:\n%s", out)
				}
			}
			if !stopping {
				t.Fatalf("STOP_PENDING missing:\n%s", out)
			}
		})
	}
}
