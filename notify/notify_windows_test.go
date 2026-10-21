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
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

const testTimeout = 5 * time.Second

var (
	runningStatus = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	startPending  = svc.Status{State: svc.StartPending}
)

// resetStatus detaches any status channel and discards any retained
// status, both now and when the test ends.
func resetStatus(t *testing.T) {
	t.Helper()
	SetGlobalStatus(nil)
	t.Cleanup(func() { SetGlobalStatus(nil) })
}

// async runs f in a goroutine and returns a channel that receives its
// result.
func async(f func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	return done
}

// attach calls SetGlobalStatus in a goroutine, since attaching may
// block until the receiver accepts the initial status.
func attach(status chan<- svc.Status) <-chan error {
	return async(func() error {
		SetGlobalStatus(status)
		return nil
	})
}

func wait(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for call to return")
	}
}

func receive(t *testing.T, status <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case s := <-status:
		return s
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for status")
		return svc.Status{}
	}
}

// expectNoMoreStatus asserts that nothing else was published. All
// senders must have returned before calling it, so a non-blocking
// receive on the unbuffered channel is conclusive.
func expectNoMoreStatus(t *testing.T, status <-chan svc.Status) {
	t.Helper()
	select {
	case s := <-status:
		t.Fatalf("unexpected extra status: %+v", s)
	default:
	}
}

func TestNotifyWithoutServiceReturnsPromptly(t *testing.T) {
	resetStatus(t)
	before := runtime.NumGoroutine()
	wait(t, async(func() error {
		for range 100 {
			for _, f := range []func() error{
				Ready,
				Reloading,
				Stopping,
				func() error { return Status("running") },
				func() error { return Error(errors.New("boom"), 1) },
			} {
				if err := f(); err != nil {
					return err
				}
			}
		}
		return nil
	}))
	// The helper goroutine may still be exiting after delivering its
	// result, so allow it a bounded amount of time to finish.
	deadline := time.Now().Add(testTimeout)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines grew from %d to %d", before, runtime.NumGoroutine())
		}
		runtime.Gosched()
	}
}

func TestAttachWithoutPriorStatusPublishesStartPending(t *testing.T) {
	resetStatus(t)
	status := make(chan svc.Status)
	attached := attach(status)
	if s := receive(t, status); s != startPending {
		t.Fatalf("initial status: expected %+v, got %+v", startPending, s)
	}
	wait(t, attached)

	ready := async(Ready)
	if s := receive(t, status); s != runningStatus {
		t.Fatalf("after Ready: expected %+v, got %+v", runningStatus, s)
	}
	wait(t, ready)
	expectNoMoreStatus(t, status)
}

func TestAttachPublishesLatestStatusReportedBeforeAttachment(t *testing.T) {
	boom := errors.New("boom")
	for i, tc := range []struct {
		name     string
		before   []func() error
		expected svc.Status
	}{
		{
			name:     "ready",
			before:   []func() error{Ready},
			expected: runningStatus,
		},
		{
			name:     "initial load",
			before:   []func() error{Reloading, Ready},
			expected: runningStatus,
		},
		{
			name:     "failed load then ready",
			before:   []func() error{Reloading, func() error { return Error(boom, 3) }, Ready},
			expected: runningStatus,
		},
		{
			name:     "reloading after ready",
			before:   []func() error{Ready, Reloading},
			expected: startPending,
		},
		{
			name:     "stopping after ready",
			before:   []func() error{Ready, Stopping},
			expected: svc.Status{State: svc.StopPending},
		},
		{
			name:     "error after ready",
			before:   []func() error{Ready, func() error { return Error(boom, 7) }},
			expected: svc.Status{State: svc.StopPending, ServiceSpecificExitCode: 7},
		},
		{
			name:     "explicit status",
			before:   []func() error{Ready, func() error { return Status("paused") }},
			expected: svc.Status{State: svc.Paused, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue},
		},
		{
			name:     "unknown status is ignored",
			before:   []func() error{Ready, func() error { return Status("bogus") }},
			expected: runningStatus,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetStatus(t)
			for _, f := range tc.before {
				if err := f(); err != nil {
					t.Fatalf("Test %d: unexpected error: %v", i, err)
				}
			}
			status := make(chan svc.Status)
			attached := attach(status)
			if s := receive(t, status); s != tc.expected {
				t.Fatalf("Test %d: expected %+v, got %+v", i, tc.expected, s)
			}
			wait(t, attached)
			expectNoMoreStatus(t, status)

			// A reload after startup is still reported normally.
			reload := async(func() error {
				if err := Reloading(); err != nil {
					return err
				}
				return Ready()
			})
			if s := receive(t, status); s != startPending {
				t.Fatalf("Test %d: reload: expected %+v, got %+v", i, startPending, s)
			}
			if s := receive(t, status); s != runningStatus {
				t.Fatalf("Test %d: reload: expected %+v, got %+v", i, runningStatus, s)
			}
			wait(t, reload)
			expectNoMoreStatus(t, status)
		})
	}
}

func TestStatusValuesAfterAttachment(t *testing.T) {
	for i, tc := range []struct {
		notify   func() error
		expected svc.Status
	}{
		{notify: Ready, expected: runningStatus},
		{notify: Reloading, expected: startPending},
		{notify: Stopping, expected: svc.Status{State: svc.StopPending}},
		{
			notify:   func() error { return Error(errors.New("boom"), 42) },
			expected: svc.Status{State: svc.StopPending, ServiceSpecificExitCode: 42},
		},
		{notify: func() error { return Status("stopped") }, expected: svc.Status{State: svc.Stopped}},
		{notify: func() error { return Status("start_pending") }, expected: startPending},
		{notify: func() error { return Status("stop_pending") }, expected: svc.Status{State: svc.StopPending}},
		{notify: func() error { return Status("RUNNING") }, expected: runningStatus},
		{notify: func() error { return Status("continue_pending") }, expected: svc.Status{State: svc.ContinuePending}},
		{notify: func() error { return Status("pause_pending") }, expected: svc.Status{State: svc.PausePending}},
		{
			notify:   func() error { return Status("paused") },
			expected: svc.Status{State: svc.Paused, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue},
		},
	} {
		resetStatus(t)
		status := make(chan svc.Status)
		attached := attach(status)
		receive(t, status)
		wait(t, attached)

		done := async(tc.notify)
		if s := receive(t, status); s != tc.expected {
			t.Errorf("Test %d: expected %+v, got %+v", i, tc.expected, s)
		}
		wait(t, done)
		expectNoMoreStatus(t, status)
	}
}

func TestUnknownStatusIsNotPublished(t *testing.T) {
	resetStatus(t)
	status := make(chan svc.Status)
	attached := attach(status)
	receive(t, status)
	wait(t, attached)

	wait(t, async(func() error { return Status("bogus") }))
	expectNoMoreStatus(t, status)
}

func TestNotificationsWaitForDelayedReceiverInOrder(t *testing.T) {
	resetStatus(t)
	status := make(chan svc.Status)
	attached := attach(status)
	if s := receive(t, status); s != startPending {
		t.Fatalf("initial status: expected %+v, got %+v", startPending, s)
	}
	wait(t, attached)

	// Nobody receives while the transitions below are sent, so they
	// must wait for the receiver rather than being dropped or reordered.
	reload := async(func() error {
		if err := Reloading(); err != nil {
			return err
		}
		return Ready()
	})
	for _, expected := range []svc.Status{startPending, runningStatus} {
		if s := receive(t, status); s != expected {
			t.Fatalf("expected %+v, got %+v", expected, s)
		}
	}
	wait(t, reload)
	expectNoMoreStatus(t, status)
}

func TestConcurrentAttachAndReady(t *testing.T) {
	for i := range 200 {
		resetStatus(t)
		status := make(chan svc.Status)
		received := make(chan []svc.Status)
		stop := make(chan struct{})
		go func() {
			var got []svc.Status
			for {
				select {
				case s := <-status:
					got = append(got, s)
				case <-stop:
					received <- got
					return
				}
			}
		}()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			SetGlobalStatus(status)
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = Ready()
		}()
		close(start)
		wg.Wait()
		close(stop)
		got := <-received

		if len(got) == 0 || got[len(got)-1] != runningStatus {
			t.Fatalf("Iteration %d: expected RUNNING last, got %+v", i, got)
		}
		for j, s := range got {
			if s == runningStatus && j != len(got)-1 {
				t.Fatalf("Iteration %d: status published after RUNNING: %+v", i, got)
			}
		}
	}
}
