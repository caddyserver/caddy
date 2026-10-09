package integration

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestStripRewritePreservesPathAuthorization(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"index.html": "ROOT INDEX SECRET",
		"bar":        "INNER SECRET",
		"secret":     "DOT SEGMENT SECRET",
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

		handle_path /foo* {
			basic_auth /* {
				alice $2a$14$DCYyqvUO/PWT.UifNF0rbuRkRfjrhHViOfVfJklmqrvWUoYcTiN2q
			}
			file_server
		}

		handle /api* {
			uri strip_prefix /api
			basic_auth /secret* {
				alice $2a$14$DCYyqvUO/PWT.UifNF0rbuRkRfjrhHViOfVfJklmqrvWUoYcTiN2q
			}
			file_server
		}

		handle /suffix* {
			uri strip_suffix /suffix
			basic_auth /* {
				alice $2a$14$DCYyqvUO/PWT.UifNF0rbuRkRfjrhHViOfVfJklmqrvWUoYcTiN2q
			}
			file_server
		}
	}
	`, filepath.ToSlash(root)), "caddyfile")

	for _, requestPath := range []string{
		"/foo",
		"/foo/",
		"/foobar",
		"/foo/index.html",
		"/api/secret",
		"/api../secret",
		"/api..%2fsecret",
		"/suffix",
	} {
		t.Run(requestPath, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://localhost:9080"+requestPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			tester.AssertResponseCode(req, http.StatusUnauthorized)
		})
	}
}
