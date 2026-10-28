package integration

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestTryFilesErrorCodeAfterQueryItem(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"style.css":  "css",
		"about.html": "about",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		grace_period 1ns
	}
	http://localhost:9080 {
		root * %q
		try_files {path} {path}.html?{query} =404
		file_server
	}
	`, filepath.ToSlash(root)), "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/style.css", 200, "css")
	tester.AssertGetResponse("http://localhost:9080/about?x=1", 200, "about")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/missing", nil)
	if err != nil {
		t.Fatal(err)
	}
	tester.AssertResponseCode(req, http.StatusNotFound)
}

func TestSkippedGroupedRouteKeepsRegexpCapture(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		grace_period 1ns
	}
	http://localhost:9080 {
		@x path_regexp x ^/x/(.*)$
		@y path_regexp x ^/(.*)$
		rewrite @x /one/{re.x.1}
		rewrite @y /two/{re.x.1}
		respond "path={path} cap={re.x.1}"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/x/q", 200, "path=/one/q cap=q")
	tester.AssertGetResponse("http://localhost:9080/z", 200, "path=/two/z cap=z")
}
