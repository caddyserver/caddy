package notify

import (
	"runtime"
	"sync"
)

// Notifier is implemented by facilities that pass fine-grained state notifications
// from this process to any concerned parties, such as init daemons.
type Notifier interface {
	// RequisiteMet returns false when calls of the Notifier will be without
	// effect because "something" is missing.
	RequisiteMet() bool

	// IsReady indicates that the process has finished starting and
	// is ready to serve according to its purpose.
	IsReady(bool) Notifier

	// IsReloading signals that the configured behaviour is about to change.
	// This could be accompanied by handing over control to a child process (see SucceededBy).
	IsReloading(bool) Notifier

	// IsStopping tells that a process is cleaning up before exiting.
	IsStopping() Notifier

	// WithStatus sets a descriptive status message.
	//
	// With init daemons such as systemd this is shown in addition to states
	// communicated by IsRead, IsReloading, IsStopping.
	// Although this sometimes can be multiple lines, the first one should
	// convey as much as possible.
	WithStatus(statusText string) Notifier

	// SucceededBy is called when a new process is taking over control from the calling one.
	SucceededBy(newMainPID int) Notifier

	// Tell pushes all outstanding state notifications to the concerned parties.
	//
	// Use this to end a chain of calls to a Notifier.
	//
	// This will be run in the main thread.
	// Run in a goroutine to avoid blocking.
	Tell()
}

var (
	allConcerned = chainNotifier{}
)

// Register a new notifier.
func Register(notifier Notifier) {
	allConcerned.Register(notifier)
}

// IsReady implements the Notifier interface.
func IsReady(yesno bool) Notifier {
	return allConcerned.IsReady(yesno)
}

// IsReloading implements the Notifier interface.
func IsReloading(yesno bool) Notifier {
	return allConcerned.IsReloading(yesno)
}

// IsStopping implements the Notifier interface.
func IsStopping() Notifier {
	return allConcerned.IsStopping()
}

// WithStatus implements the Notifier interface.
func WithStatus(statusText string) Notifier {
	return allConcerned.WithStatus(statusText)
}

// SucceededBy implements the Notifier interface.
func SucceededBy(newMainPID int) Notifier {
	return allConcerned.SucceededBy(newMainPID)
}

type chainNotifier struct {
	Notifier

	otherLock sync.RWMutex
	other     []Notifier
}

// Register appends the Notifier to the notification chain.
func (p *chainNotifier) Register(notifier Notifier) {
	p.otherLock.Lock()
	defer p.otherLock.Unlock()

	if p.other == nil {
		p.other = []Notifier{}
	}
	p.other = append(p.other, notifier)
}

func (p *chainNotifier) RequisiteMet() bool {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()
	return p.other != nil
}

func (p *chainNotifier) IsReady(yesno bool) Notifier {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()
	for _, n := range p.other {
		if !n.RequisiteMet() {
			continue
		}
		n.IsReady(yesno)
	}
	return p
}

func (p *chainNotifier) IsReloading(yesno bool) Notifier {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()
	for _, n := range p.other {
		if !n.RequisiteMet() {
			continue
		}
		n.IsReloading(yesno)
	}
	return p
}

func (p *chainNotifier) IsStopping() Notifier {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()
	for _, n := range p.other {
		if !n.RequisiteMet() {
			continue
		}
		n.IsStopping()
	}
	return p
}

func (p *chainNotifier) WithStatus(statusText string) Notifier {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()
	for _, n := range p.other {
		if !n.RequisiteMet() {
			continue
		}
		n.WithStatus(statusText)
	}
	return p
}

func (p *chainNotifier) SucceededBy(newMainPID int) Notifier {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()
	for _, n := range p.other {
		if !n.RequisiteMet() {
			continue
		}
		n.SucceededBy(newMainPID)
	}
	return p
}

func (p *chainNotifier) Tell() {
	p.otherLock.RLock()
	defer p.otherLock.RUnlock()

	if p.other == nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for _, n := range p.other {
		if !n.RequisiteMet() {
			continue
		}
		n.Tell()
	}
	return
}
