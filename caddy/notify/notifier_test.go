package notify

import (
	"strconv"
	"testing"
)

// testingNotifier is used for and in tests.
type testingNotifier struct {
	Notifier

	pendingLines []string
	requisiteMet bool
}

// NewSystemdNotifier checks if we could talk to a systemd daemon
// and returns an instance of SystemdNotifier initialized accordingly.
func newTestingNotifier() *testingNotifier {
	p := new(testingNotifier)
	p.pendingLines = []string{}
	p.requisiteMet = true
	return p
}

func (p *testingNotifier) RequisiteMet() bool {
	return p.requisiteMet
}

func (p *testingNotifier) IsReady(yesno bool) Notifier {
	if yesno {
		p.pendingLines = append(p.pendingLines, "READY=1")
	} else {
		p.pendingLines = append(p.pendingLines, "READY=0")
	}
	return p
}

func (p *testingNotifier) IsReloading(yesno bool) Notifier {
	if yesno {
		p.pendingLines = append(p.pendingLines, "RELOADING=1")
	} else {
		p.pendingLines = append(p.pendingLines, "RELOADING=0")
	}
	return p
}

func (p *testingNotifier) IsStopping() Notifier {
	p.pendingLines = append(p.pendingLines, "STOPPING=1")
	return p
}

func (p *testingNotifier) WithStatus(statusText string) Notifier {
	p.pendingLines = append(p.pendingLines, statusText) // no STATUS= here
	return p
}

func (p *testingNotifier) SucceededBy(newMainPID int) Notifier {
	p.pendingLines = append(p.pendingLines, "MAINPID="+strconv.Itoa(newMainPID))
	return p
}

func (p *testingNotifier) Tell() {
	p.pendingLines = []string{}
}

func TestNotifier(t *testing.T) {
	allConcerned.other = []Notifier{}
	defer func() {
		allConcerned.other = []Notifier{}
	}()
	agent := newTestingNotifier()
	Register(agent)
	if len(allConcerned.other) != 1 {
		t.Fatalf("Registration failed, expected 1, got %d registered Notifier", len(allConcerned.other))
	}
	if len(allConcerned.other) > 0 && allConcerned.other[0] == nil {
		t.Fatalf("nil in list of Notifiers: %#v", allConcerned.other)
	}

	n := WithStatus("AAA")
	if len(agent.pendingLines) != 1 {
		t.Fatalf("Notifier has unexpected artifacts %#v", agent.pendingLines)
	}
	if len(agent.pendingLines) > 0 && agent.pendingLines[0] != "AAA" {
		t.Fatalf("Notifier has not picked up the status text %#v", agent.pendingLines)
	}
	if n == nil {
		t.Fatal("Method returned nil")
	}

	n.Tell()
	if len(agent.pendingLines) != 0 {
		t.Fatalf("Notifier has not been cleared %#v", agent.pendingLines)
	}

	agent.requisiteMet = false
	WithStatus("BBB")
	if len(agent.pendingLines) != 0 {
		t.Fatalf("Notifier has been called, but shouldn't: %#v", agent.pendingLines)
	}
	agent.requisiteMet = true

	n = IsReady(true)
	if len(agent.pendingLines) != 1 && agent.pendingLines[0] != "READY=1" {
		t.Errorf("IsReady did not work: %#v", agent.pendingLines)
	}
	n.Tell()

	n = IsReloading(true)
	if len(agent.pendingLines) != 1 && agent.pendingLines[0] != "RELOADING=1" {
		t.Errorf("IsReloading did not work: %#v", agent.pendingLines)
	}
	n.Tell()

	n = IsStopping()
	if len(agent.pendingLines) != 1 && agent.pendingLines[0] != "STOPPING=1" {
		t.Errorf("IsStopping did not work: %#v", agent.pendingLines)
	}
	n.Tell()

	n = SucceededBy(4) // 4 is the "Sony Memorial Random Number"
	if len(agent.pendingLines) != 1 && agent.pendingLines[0] != "MAINPID=4" {
		t.Errorf("SucceededBy did not work: %#v", agent.pendingLines)
	}
	n.Tell()

	IsReady(true).WithStatus("Serving").Tell()
	if len(agent.pendingLines) != 0 {
		t.Fatalf("Notifier has not been cleared %#v", agent.pendingLines)
	}
}
