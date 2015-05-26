package git

import (
	"fmt"
	"testing"
	"time"

	"github.com/mholt/caddy/middleware/git/gittest"
)

func init() {
	SetOS(gittest.FakeOS)
}

func Test(t *testing.T) {
	repo := &Repo{URL: "git@github.com", Interval: time.Second}

	Start(repo)
	if len(Monitor.services) != 1 {
		t.Errorf("Expected 1 service, found %v", len(Monitor.services))
	}

	Monitor.StopAndWait(repo.URL, 1)
	if len(Monitor.services) != 0 {
		t.Errorf("Expected 1 service, found %v", len(Monitor.services))
	}

	repos := make([]*Repo, 5)
	for i := 0; i < 5; i++ {
		repos[i] = &Repo{URL: fmt.Sprintf("test%v", i), Interval: time.Second * 2}
		Start(repos[i])
		if len(Monitor.services) != i+1 {
			t.Errorf("Expected %v service(s), found %v", i+1, len(Monitor.services))
		}
	}

	time.Sleep(time.Second * 5)
	Monitor.StopAndWait(repos[0].URL, 1)
	if len(Monitor.services) != 4 {
		t.Errorf("Expected %v service(s), found %v", 4, len(Monitor.services))
	}

	repo = &Repo{URL: "git@github.com", Interval: time.Second}
	Start(repo)
	if len(Monitor.services) != 5 {
		t.Errorf("Expected %v service(s), found %v", 5, len(Monitor.services))
	}

	repo = &Repo{URL: "git@github.com", Interval: time.Second * 2}
	Start(repo)
	if len(Monitor.services) != 6 {
		t.Errorf("Expected %v service(s), found %v", 6, len(Monitor.services))
	}

	time.Sleep(time.Second * 5)
	Monitor.StopAndWait(repo.URL, -1)
	if len(Monitor.services) != 4 {
		t.Errorf("Expected %v service(s), found %v", 4, len(Monitor.services))
	}
}
