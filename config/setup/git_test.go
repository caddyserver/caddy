package setup

import (
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/mholt/caddy/middleware/git"
	"github.com/mholt/caddy/middleware/git/gittest"
)

// init sets the OS used to fakeOS
func init() {
	git.SetOS(gittest.FakeOS)
}

func check(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
}

func TestGit(t *testing.T) {
	c := newTestController(`git git@github.com:mholt/caddy.git`)

	mid, err := Git(c)
	check(t, err)
	if mid != nil {
		t.Fatal("Git middleware is a background service and expected to be nil.")
	}
}

func TestIntervals(t *testing.T) {
	tests := []string{
		`git git@github.com:user/repo { interval 10 }`,
		`git git@github.com:user/repo { interval 5 }`,
		`git git@github.com:user/repo { interval 2 }`,
		`git git@github.com:user/repo { interval 1 }`,
		`git git@github.com:user/repo { interval 6 }`,
	}

	for i, test := range tests {
		git.Logger = nil

		c1 := newTestController(test)
		repo, err := gitParse(c1)
		check(t, err)

		c2 := newTestController(test)
		_, err = Git(c2)
		check(t, err)

		// start startup services
		err = c2.Startup[0]()
		check(t, err)

		// wait for first background pull
		gittest.Sleep(time.Millisecond * 100)

		// switch logger to test file
		logFile := gittest.Open("file")
		git.Logger = log.New(logFile, "", 0)

		// sleep for the interval
		gittest.Sleep(repo.Interval)

		// get log output
		out, err := ioutil.ReadAll(logFile)
		check(t, err)

		// if greater than minimum interval
		if repo.Interval >= time.Second*5 {
			expected := `https://github.com/user/repo.git pulled.
No new changes.`

			// ensure pull is done by tracing the output
			if expected != strings.TrimSpace(string(out)) {
				t.Errorf("Test %v: Expected %v found %v", i, expected, string(out))
			}
		} else {
			// ensure pull is ignored by confirming no output
			if string(out) != "" {
				t.Errorf("Test %v: Expected no output but found %v", i, string(out))
			}
		}

		// stop background thread monitor
		git.Services.Stop(repo.URL, 1)

	}

}

func TestGitParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  *git.Repo
	}{
		{`git git@github.com:user/repo`, false, &git.Repo{
			URL: "https://github.com/user/repo.git",
		}},
		{`git github.com/user/repo`, false, &git.Repo{
			URL: "https://github.com/user/repo.git",
		}},
		{`git git@github.com/user/repo`, true, nil},
		{`git http://github.com/user/repo`, false, &git.Repo{
			URL: "https://github.com/user/repo.git",
		}},
		{`git https://github.com/user/repo`, false, &git.Repo{
			URL: "https://github.com/user/repo.git",
		}},
		{`git http://github.com/user/repo {
			key ~/.key
		}`, false, &git.Repo{
			KeyPath: "~/.key",
			URL:     "git@github.com:user/repo.git",
		}},
		{`git git@github.com:user/repo {
			key ~/.key
		}`, false, &git.Repo{
			KeyPath: "~/.key",
			URL:     "git@github.com:user/repo.git",
		}},
		{`git `, true, nil},
		{`git {
		}`, true, nil},
		{`git {
		repo git@github.com:user/repo.git`, true, nil},
		{`git {
		repo git@github.com:user/repo
		key ~/.key
		}`, false, &git.Repo{
			KeyPath: "~/.key",
			URL:     "git@github.com:user/repo.git",
		}},
		{`git {
		repo git@github.com:user/repo
		key ~/.key
		interval 600
		}`, false, &git.Repo{
			KeyPath:  "~/.key",
			URL:      "git@github.com:user/repo.git",
			Interval: time.Second * 600,
		}},
		{`git {
		repo git@github.com:user/repo
		branch dev
		}`, false, &git.Repo{
			Branch: "dev",
			URL:    "https://github.com/user/repo.git",
		}},
		{`git {
		key ~/.key
		}`, true, nil},
		{`git {
		repo git@github.com:user/repo
		key ~/.key
		then echo hello world
		}`, false, &git.Repo{
			KeyPath: "~/.key",
			URL:     "git@github.com:user/repo.git",
			Then:    "echo hello world",
		}},
	}

	for i, test := range tests {
		c := newTestController(test.input)
		repo, err := gitParse(c)
		if !test.shouldErr && err != nil {
			t.Errorf("Test %v should not error but found %v", i, err)
			continue
		}
		if test.shouldErr && err == nil {
			t.Errorf("Test %v should error but found nil", i)
			continue
		}
		if !reposEqual(test.expected, repo) {
			t.Errorf("Test %v expects %v but found %v", i, test.expected, repo)
		}
	}
}

func reposEqual(expected, repo *git.Repo) bool {
	if expected == nil {
		return repo == nil
	}
	if expected.Branch != "" && expected.Branch != repo.Branch {
		return false
	}
	if expected.Host != "" && expected.Host != repo.Host {
		return false
	}
	if expected.Interval != 0 && expected.Interval != repo.Interval {
		return false
	}
	if expected.KeyPath != "" && expected.KeyPath != repo.KeyPath {
		return false
	}
	if expected.Path != "" && expected.Path != repo.Path {
		return false
	}
	if expected.Then != "" && expected.Then != repo.Then {
		return false
	}
	if expected.URL != "" && expected.URL != repo.URL {
		return false
	}
	return true
}
