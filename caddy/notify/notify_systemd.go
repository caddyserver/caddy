// +build linux

package notify

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-systemd/daemon"
)

// SystemdNotifier interfaces with systemd.
type SystemdNotifier struct {
	Notifier

	pendingLock  sync.RWMutex
	pendingLines []string

	// haveSystemd is 'true' when the process has been started by systemd.
	haveSystemd bool

	// Used in limiting calls to systemd to one at a time.
	commsLock sync.Mutex
}

// NewSystemdNotifier checks if we could talk to a systemd daemon
// and returns an instance of SystemdNotifier initialized accordingly.
func NewSystemdNotifier() *SystemdNotifier {
	p := new(SystemdNotifier)
	p.haveSystemd = os.Getenv("NOTIFY_SOCKET") != ""
	p.pendingLines = []string{}
	return p
}

func init() {
	Register(NewSystemdNotifier())
}

// RequisiteMet returns true if at initialization of this Notifier implementation
// systemd has been available to listen to any notifications.
func (p *SystemdNotifier) RequisiteMet() bool {
	return p.haveSystemd
}

// IsReady triggers start of any remaining services that depend on this one.
func (p *SystemdNotifier) IsReady(yesno bool) Notifier {
	p.pendingLock.Lock()
	defer p.pendingLock.Unlock()
	if yesno {
		p.pendingLines = append(p.pendingLines, "READY=1")
	} else {
		p.pendingLines = append(p.pendingLines, "READY=0")
	}
	return p
}

// IsReloading implements the Notifier interface.
func (p *SystemdNotifier) IsReloading(yesno bool) Notifier {
	p.pendingLock.Lock()
	defer p.pendingLock.Unlock()
	if yesno {
		p.pendingLines = append(p.pendingLines, "RELOADING=1")
	} else {
		p.pendingLines = append(p.pendingLines, "RELOADING=0")
	}
	return p
}

// IsStopping implements the Notifier interface.
func (p *SystemdNotifier) IsStopping() Notifier {
	p.pendingLock.Lock()
	defer p.pendingLock.Unlock()
	p.pendingLines = append(p.pendingLines, "STOPPING=1")
	return p
}

// WithStatus is used to add a line to systemd's 'Status' roster.
func (p *SystemdNotifier) WithStatus(statusText string) Notifier {
	p.pendingLock.Lock()
	defer p.pendingLock.Unlock()
	p.pendingLines = append(p.pendingLines, "STATUS="+statusText)
	return p
}

// SucceededBy implements the Notifier interface.
//
// If 'NotifyAccess=main' has been set in the systemd service file,
// then systemd will stop getting status messages from this process and
// listen to the child identified by the newMainPID.
func (p *SystemdNotifier) SucceededBy(newMainPID int) Notifier {
	p.pendingLock.Lock()
	defer p.pendingLock.Unlock()
	p.pendingLines = append(p.pendingLines, "MAINPID="+strconv.Itoa(newMainPID))
	return p
}

// Tell implements the Notifier interface.
//
// This connects with systemd and could hang.
func (p *SystemdNotifier) Tell() {
	p.commsLock.Lock()
	defer p.commsLock.Unlock()
	p.pendingLock.Lock()
	defer p.pendingLock.Unlock()

	err := daemon.SdNotify(strings.Join(p.pendingLines, "\n"))
	p.pendingLines = []string{}

	if err == daemon.SdNotifyNoSocket {
		p.haveSystemd = false
	}
}
