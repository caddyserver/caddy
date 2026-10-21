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

	"golang.org/x/sys/windows/svc"

	"github.com/caddyserver/caddy/v2/notify"
)

const serviceTestTimeout = 5 * time.Second

var (
	serviceRunning      = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	serviceStartPending = svc.Status{State: svc.StartPending}
)

// startRunner starts runner.Execute with unbuffered channels, like the
// x/sys/windows/svc dispatcher. The runner only returns by exiting the
// process, so its goroutine stays parked on the request channel after
// the test; the notify channel is detached on cleanup so nothing sends
// to it afterwards.
func startRunner(t *testing.T) (chan<- svc.ChangeRequest, <-chan svc.Status) {
	t.Helper()
	requests := make(chan svc.ChangeRequest)
	status := make(chan svc.Status)
	go runner{}.Execute(nil, requests, status)
	t.Cleanup(func() { notify.SetGlobalStatus(nil) })
	return requests, status
}

func receiveServiceStatus(t *testing.T, status <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case s := <-status:
		return s
	case <-time.After(serviceTestTimeout):
		t.Fatal("timed out waiting for service status")
		return svc.Status{}
	}
}

func sendServiceRequest(t *testing.T, requests chan<- svc.ChangeRequest, req svc.ChangeRequest) {
	t.Helper()
	select {
	case requests <- req:
	case <-time.After(serviceTestTimeout):
		t.Fatal("timed out sending service request")
	}
}

// interrogate sends an Interrogate request and checks that the runner
// echoes the given current status. Because the runner handles requests
// only after its initial status is published, this also acts as a
// barrier for startup.
func interrogate(t *testing.T, requests chan<- svc.ChangeRequest, status <-chan svc.Status, current svc.Status) {
	t.Helper()
	sendServiceRequest(t, requests, svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: current})
	if s := receiveServiceStatus(t, status); s != current {
		t.Fatalf("interrogate: expected %+v, got %+v", current, s)
	}
}

// reload performs the notifications caddy.Load sends for a successful
// config load and checks that they are published in order.
func reload(t *testing.T, status <-chan svc.Status) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if err := notify.Reloading(); err != nil {
			done <- err
			return
		}
		done <- notify.Ready()
	}()
	if s := receiveServiceStatus(t, status); s != serviceStartPending {
		t.Fatalf("reload: expected %+v, got %+v", serviceStartPending, s)
	}
	if s := receiveServiceStatus(t, status); s != serviceRunning {
		t.Fatalf("reload: expected %+v, got %+v", serviceRunning, s)
	}
	if err := <-done; err != nil {
		t.Fatalf("reload: %v", err)
	}
}

func TestServiceReadyBeforeExecute(t *testing.T) {
	notify.SetGlobalStatus(nil)
	// The initial config load finishes before the service handler starts.
	if err := notify.Reloading(); err != nil {
		t.Fatal(err)
	}
	if err := notify.Ready(); err != nil {
		t.Fatal(err)
	}

	requests, status := startRunner(t)
	if s := receiveServiceStatus(t, status); s != serviceRunning {
		t.Fatalf("expected %+v, got %+v", serviceRunning, s)
	}
	interrogate(t, requests, status, serviceRunning)
	reload(t, status)
}

func TestServiceExecuteBeforeReady(t *testing.T) {
	notify.SetGlobalStatus(nil)
	requests, status := startRunner(t)
	if s := receiveServiceStatus(t, status); s != serviceStartPending {
		t.Fatalf("expected %+v, got %+v", serviceStartPending, s)
	}
	interrogate(t, requests, status, serviceStartPending)

	done := make(chan error, 1)
	go func() { done <- notify.Ready() }()
	if s := receiveServiceStatus(t, status); s != serviceRunning {
		t.Fatalf("expected %+v, got %+v", serviceRunning, s)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	interrogate(t, requests, status, serviceRunning)
	reload(t, status)
}

func TestServiceReadyRacesExecute(t *testing.T) {
	// A sentinel checkpoint marks the Interrogate reply so the collector
	// knows every earlier status has been received.
	const sentinel = 0x8262
	for i := range 50 {
		notify.SetGlobalStatus(nil)
		requests := make(chan svc.ChangeRequest)
		status := make(chan svc.Status)
		received := make(chan []svc.Status, 1)
		go func() {
			var got []svc.Status
			for s := range status {
				if s.CheckPoint == sentinel {
					received <- got
					return
				}
				got = append(got, s)
			}
		}()

		start := make(chan struct{})
		go func() {
			<-start
			runner{}.Execute(nil, requests, status)
		}()
		readyDone := make(chan struct{})
		go func() {
			defer close(readyDone)
			<-start
			_ = notify.Ready()
		}()
		close(start)

		select {
		case <-readyDone:
		case <-time.After(serviceTestTimeout):
			t.Fatalf("Iteration %d: Ready did not return", i)
		}
		sendServiceRequest(t, requests, svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{CheckPoint: sentinel}})

		var got []svc.Status
		select {
		case got = <-received:
		case <-time.After(serviceTestTimeout):
			t.Fatalf("Iteration %d: timed out collecting statuses", i)
		}
		notify.SetGlobalStatus(nil)

		if len(got) == 0 || got[len(got)-1] != serviceRunning {
			t.Fatalf("Iteration %d: expected RUNNING last, got %+v", i, got)
		}
		for j, s := range got {
			if s == serviceRunning && j != len(got)-1 {
				t.Fatalf("Iteration %d: stale status published after RUNNING: %+v", i, got)
			}
		}
	}
}

// TestServiceStopAndShutdown runs the runner in a child process, since
// handling Stop or Shutdown exits the process.
func TestServiceStopAndShutdown(t *testing.T) {
	const envKey = "CADDY_TEST_SERVICE_CONTROL"
	if cmd := os.Getenv(envKey); cmd != "" {
		runServiceControlChild(cmd)
		return
	}

	for _, cmd := range []string{"stop", "shutdown"} {
		t.Run(cmd, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServiceStopAndShutdown$", "-test.count=1")
			child.Env = append(os.Environ(), envKey+"="+cmd)
			out, err := child.Output()
			if err != nil {
				t.Fatalf("child process failed: %v; stdout:\n%s", err, out)
			}
			expected := []string{
				fmt.Sprintf("status %d %d", svc.StartPending, 0),
				fmt.Sprintf("status %d %d", svc.Running, svc.AcceptStop|svc.AcceptShutdown),
				fmt.Sprintf("status %d %d", svc.StopPending, 0),
			}
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) < len(expected) {
				t.Fatalf("expected at least %d statuses, got:\n%s", len(expected), out)
			}
			for i, want := range expected {
				if lines[i] != want {
					t.Fatalf("status %d: expected %q, got %q; stdout:\n%s", i, want, lines[i], out)
				}
			}
		})
	}
}

// runServiceControlChild prints each status the runner publishes and
// sends the requested control. It exits with a distinct code if the
// runner fails to exit the process.
func runServiceControlChild(cmd string) {
	requests := make(chan svc.ChangeRequest)
	status := make(chan svc.Status)
	go runner{}.Execute(nil, requests, status)
	printStatus := func(s svc.Status) { fmt.Printf("status %d %d\n", s.State, s.Accepts) }

	// Receive the initial status before calling Ready so the output
	// order is deterministic.
	printStatus(<-status)
	go func() {
		if err := notify.Ready(); err != nil {
			os.Exit(4)
		}
	}()
	printStatus(<-status)
	go func() {
		for s := range status {
			printStatus(s)
		}
	}()

	ctl := svc.Stop
	if cmd == "shutdown" {
		ctl = svc.Shutdown
	}
	requests <- svc.ChangeRequest{Cmd: ctl}
	time.Sleep(serviceTestTimeout)
	os.Exit(5)
}
