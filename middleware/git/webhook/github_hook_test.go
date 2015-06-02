package webhook

import (
	"bytes"
	"github.com/mholt/caddy/middleware/git"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGithubDeployPush(t *testing.T) {
	repo := &git.Repo{Branch: "master", HookUrl: "/github_deploy", HookSecret: "supersecret"}
	ghHook := GithubHook{}

	for i, test := range []struct {
		body         string
		event        string
		responseBody string
		code         int
	}{
		{"", "", "", 400},
		{"", "push", "", 400},
		{pushBodyOther, "push", "", 200},
		{pushBodyPartial, "push", "", 400},
		{"", "release", "", 400},
		{"", "ping", "pong", 200},
	} {

		req, err := http.NewRequest("POST", "/github_deploy", bytes.NewBuffer([]byte(test.body)))
		if err != nil {
			t.Fatalf("Test %v: Could not create HTTP request: %v", i, err)
		}

		if test.event != "" {
			req.Header.Add("X-Github-Event", test.event)
		}

		rec := httptest.NewRecorder()

		code, err := ghHook.Handle(rec, req, repo)

		if code != test.code {
			t.Errorf("Test %d: Expected response code to be %d but was %d", i, test.code, code)
		}

		if rec.Body.String() != test.responseBody {
			t.Errorf("Test %d: Expected response body to be '%v' but was '%v'", i, test.responseBody, rec.Body.String())
		}
	}

}

var pushBodyPartial = `
{
  "ref": ""
}
`

var pushBodyOther = `
{
  "ref": "refs/heads/some-other-branch"
}
`
