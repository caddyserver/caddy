package integration

import (
	"net/http"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// TestReloadConcurrent exercises reload under concurrent conditions
// and is most useful under test with `-race` enabled.
func TestReloadConcurrent(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
	}

	localhost:9080 {
		root * testdata/
	}
	`, "caddyfile")

	const configURL = "http://localhost:2999/config/apps/http"

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			resp1, err := tester.Client.Get(configURL)
			if err != nil {
				t.Errorf("cannot get app config %s", err)

				return
			}

			r, err := http.NewRequest("POST", configURL, resp1.Body)
			if err != nil {
				t.Errorf("cannot create request %s", err)

				return
			}
			r.Header.Add("Content-Type", "application/json")
			r.Header.Add("Cache-Control", "must-revalidate")

			resp, err := tester.Client.Do(r)
			if err != nil {
				t.Errorf("cannot reload app config %s", err)

				return
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200; got %d", resp.StatusCode)

				return
			}
		}()
	}
	wg.Wait()
}
