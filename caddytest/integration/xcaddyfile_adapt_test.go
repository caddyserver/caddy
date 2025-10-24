package integration

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/httpserverblock"
)

// TestXCaddyfileAdaptBackwardsCompatibility ensures that xcaddyfile produces
// the same output as the standard caddyfile adapter for all test cases when
// using standard Caddyfile syntax (without explicit [type] declarations).
// This verifies perfect backwards compatibility.
func TestXCaddyfileAdaptBackwardsCompatibility(t *testing.T) {
	// load the list of test files from the caddyfile_adapt dir
	files, err := os.ReadDir("./caddyfile_adapt")
	if err != nil {
		t.Errorf("failed to read caddyfile_adapt dir: %s", err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		filename := f.Name()

		// run each file as a subtest
		t.Run(filename, func(t *testing.T) {
			// read the test file
			data, err := os.ReadFile("./caddyfile_adapt/" + filename)
			if err != nil {
				t.Errorf("failed to read %s: %s", filename, err)
				return
			}

			// split the Caddyfile (first) and JSON (second) parts
			parts := strings.Split(string(data), "----------")
			if len(parts) < 2 {
				t.Logf("skipping %s: no expected output section", filename)
				return
			}

			caddyfile := strings.TrimSpace(parts[0]) + "\n"
			expected := strings.TrimSpace(parts[1])

			// only test JSON outputs (skip error tests)
			if len(expected) == 0 || expected[0] != '{' {
				t.Logf("skipping %s: not a JSON output test", filename)
				return
			}

			// adapt with standard caddyfile adapter
			caddyfileAdapter := caddyconfig.GetAdapter("caddyfile")
			caddyfileCfg, caddyfileWarnings, caddyfileErr := caddyfileAdapter.Adapt([]byte(caddyfile), nil)
			if caddyfileErr != nil {
				t.Logf("skipping %s: caddyfile adapter error: %v", filename, caddyfileErr)
				return
			}

			// adapt with xcaddyfile adapter
			xcaddyfileAdapter := caddyconfig.GetAdapter("xcaddyfile")
			xcaddyfileCfg, xcaddyfileWarnings, xcaddyfileErr := xcaddyfileAdapter.Adapt([]byte(caddyfile), nil)

			// both should succeed
			if xcaddyfileErr != nil {
				t.Errorf("xcaddyfile adapter failed for %s: %v", filename, xcaddyfileErr)
				return
			}

			// compare warning counts (log if different)
			if len(caddyfileWarnings) != len(xcaddyfileWarnings) {
				t.Logf("warning count differs for %s: caddyfile=%d, xcaddyfile=%d",
					filename, len(caddyfileWarnings), len(xcaddyfileWarnings))
			}

			// unmarshal both configs for comparison
			var caddyfileJSON, xcaddyfileJSON map[string]interface{}
			if err := json.Unmarshal(caddyfileCfg, &caddyfileJSON); err != nil {
				t.Errorf("failed to unmarshal caddyfile config for %s: %v", filename, err)
				return
			}
			if err := json.Unmarshal(xcaddyfileCfg, &xcaddyfileJSON); err != nil {
				t.Errorf("failed to unmarshal xcaddyfile config for %s: %v", filename, err)
				return
			}

			// marshal back to compare as strings (for easier debugging)
			caddyfileStr, _ := json.MarshalIndent(caddyfileJSON, "", "  ")
			xcaddyfileStr, _ := json.MarshalIndent(xcaddyfileJSON, "", "  ")

			if string(caddyfileStr) != string(xcaddyfileStr) {
				t.Errorf("config mismatch for %s:\n\nCaddyfile output:\n%s\n\nXCaddyfile output:\n%s",
					filename, caddyfileStr, xcaddyfileStr)
			}
		})
	}
}
