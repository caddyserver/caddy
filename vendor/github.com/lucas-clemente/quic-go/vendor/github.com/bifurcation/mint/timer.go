package mint

import (
	"time"
)

// This is a simple timer implementation. Timers are stored in a sorted
// list.
// TODO(ekr@rtfm.com): Add a way to uncouple these from the system
// clock.
type timerCb func() error

type timer struct {
	label    string
	cb       timerCb
	deadline time.Time
	duration uint32
}

type timerSet struct {
	ts []*timer
}

func newTimerSet() *timerSet {
	return &timerSet{}
}

func (ts *timerSet) start(label string, cb timerCb, delayMs uint32) *timer {
	now := time.Now()
	t := timer{
		label,
		cb,
		now.Add(time.Millisecond * time.Duration(delayMs)),
		delayMs,
	}
	logf(logTypeHandshake, "Timer %s set [%v -> %v]", t.label, now, t.deadline)

	var i int
	ntimers := len(ts.ts)
	for i = 0; i < ntimers; i++ {
		if t.deadline.Before(ts.ts[i].deadline) {
			break
		}
	}

	tmp := make([]*timer, 0, ntimers+1)
	tmp = append(tmp, ts.ts[:i]...)
	tmp = append(tmp, &t)
	tmp = append(tmp, ts.ts[i:]...)
	ts.ts = tmp

	return &t
}

// TODO(ekr@rtfm.com): optimize this now that the list is sorted.
// We should be able to do just one list manipulation, as long
// as we're careful about how we handle inserts during callbacks.
func (ts *timerSet) check(now time.Time) error {
	for i, t := range ts.ts {
		if now.After(t.deadline) {
			ts.ts = append(ts.ts[:i], ts.ts[:i+1]...)
			if t.cb != nil {
				logf(logTypeHandshake, "Timer %s expired [%v > %v]", t.label, now, t.deadline)
				cb := t.cb
				t.cb = nil
				err := cb()
				if err != nil {
					return err
				}
			}
		} else {
			break
		}
	}
	return nil
}

// Returns the next time any of the timers would fire.
func (ts *timerSet) remaining() (bool, time.Duration) {
	for _, t := range ts.ts {
		if t.cb != nil {
			return true, time.Until(t.deadline)
		}
	}

	return false, time.Duration(0)
}

func (ts *timerSet) cancel(label string) {
	for _, t := range ts.ts {
		if t.label == label {
			t.cancel()
		}
	}
}

func (ts *timerSet) getTimer(label string) *timer {
	for _, t := range ts.ts {
		if t.label == label && t.cb != nil {
			return t
		}
	}
	return nil
}

func (ts *timerSet) getAllTimers() []string {
	var ret []string

	for _, t := range ts.ts {
		if t.cb != nil {
			ret = append(ret, t.label)
		}
	}

	return ret
}

func (t *timer) cancel() {
	logf(logTypeHandshake, "Timer %s cancelled", t.label)
	t.cb = nil
	t.label = ""
}
