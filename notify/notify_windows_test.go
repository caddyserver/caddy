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

func resetStatus() {
	statusMu.Lock()
	globalStatus = nil
	pendingStatus = nil
	statusMu.Unlock()
}

func receive(t *testing.T, ch <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no status was sent to the SCM")
		return svc.Status{}
	}
}

func expectNothing(t *testing.T, ch <-chan svc.Status) {
	t.Helper()
	select {
	case s := <-ch:
		t.Fatalf("unexpected status sent to the SCM: %+v", s)
	case <-time.After(100 * time.Millisecond):
	}
}

// The config can finish loading, and Ready be called, before the SCM
// invokes the service handler that registers the status channel. The
// Running status must still reach the SCM.
func TestReadyBeforeSetGlobalStatusIsDelivered(t *testing.T) {
	resetStatus()
	if err := Ready(); err != nil {
		t.Fatal(err)
	}

	ch := make(chan svc.Status, 1)
	SetGlobalStatus(ch)

	got := receive(t, ch)
	if got.State != svc.Running {
		t.Errorf("state = %v, want Running", got.State)
	}
	if got.Accepts != svc.AcceptStop|svc.AcceptShutdown {
		t.Errorf("accepts = %v, want stop and shutdown", got.Accepts)
	}
	expectNothing(t, ch)
}

func TestReadyAfterSetGlobalStatusIsDelivered(t *testing.T) {
	resetStatus()
	ch := make(chan svc.Status, 1)
	SetGlobalStatus(ch)
	expectNothing(t, ch)

	if err := Ready(); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, ch); got.State != svc.Running {
		t.Errorf("state = %v, want Running", got.State)
	}
}

func TestLastStatusBeforeSetGlobalStatusWins(t *testing.T) {
	resetStatus()
	if err := Ready(); err != nil {
		t.Fatal(err)
	}
	if err := Error(nil, 7); err != nil {
		t.Fatal(err)
	}

	ch := make(chan svc.Status, 2)
	SetGlobalStatus(ch)

	got := receive(t, ch)
	if got.State != svc.StopPending || got.ServiceSpecificExitCode != 7 {
		t.Errorf("got %+v, want StopPending with exit code 7", got)
	}
	expectNothing(t, ch)
}

func TestPendingStatusIsDeliveredOnlyOnce(t *testing.T) {
	resetStatus()
	if err := Ready(); err != nil {
		t.Fatal(err)
	}

	first := make(chan svc.Status, 1)
	SetGlobalStatus(first)
	receive(t, first)

	second := make(chan svc.Status, 1)
	SetGlobalStatus(second)
	expectNothing(t, second)
}

func TestStatusByNameBeforeSetGlobalStatus(t *testing.T) {
	resetStatus()
	if err := Status("bogus"); err != nil {
		t.Fatal(err)
	}
	if err := Status("paused"); err != nil {
		t.Fatal(err)
	}

	ch := make(chan svc.Status, 1)
	SetGlobalStatus(ch)

	got := receive(t, ch)
	if got.State != svc.Paused {
		t.Errorf("state = %v, want Paused", got.State)
	}
	expectNothing(t, ch)
}

// A status requested before the channel was registered must not be delivered
// after a status requested later: the SCM would then be left believing the
// service is Running while it is already stopping. That requires registration
// and replay to be atomic with respect to other senders - if the channel
// became reachable before the remembered status was in it, a concurrent
// Stopping() could slip StopPending in first.
//
// The inversion itself is a window of a few hundred nanoseconds and does not
// reproduce reliably, so what is pinned here is the property that rules it
// out: while the replayed status is in flight, no other sender can reach the
// channel.
func TestRegistrationAndReplayDoNotInterleaveWithOtherSenders(t *testing.T) {
	resetStatus()
	if err := Ready(); err != nil {
		t.Fatal(err)
	}

	// Unbuffered and not received from yet, so the replayed status stays in
	// flight for as long as this test wants it to.
	ch := make(chan svc.Status)
	registered := make(chan struct{})
	go func() {
		defer close(registered)
		SetGlobalStatus(ch)
	}()

	// Wait for the replay to be under way, and check throughout that the
	// channel has not become reachable to anyone else in the meantime.
	var interleaved bool
	for range 200 {
		if statusMu.TryLock() {
			reachable := globalStatus != nil
			statusMu.Unlock()
			if reachable {
				interleaved = true
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if interleaved {
		// Release the sender before failing, so that the rest of the
		// package does not block on the status lock it may be holding.
		receive(t, ch)
		<-registered
		t.Fatal("channel is reachable to other senders while the replayed status is still in flight")
	}

	// A status requested now cannot overtake the replayed one.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = Stopping()
	}()

	if got := receive(t, ch); got.State != svc.Running {
		t.Fatalf("first status = %v, want Running", got.State)
	}
	if got := receive(t, ch); got.State != svc.StopPending {
		t.Fatalf("second status = %v, want StopPending", got.State)
	}
	<-registered
	<-stopped
}
