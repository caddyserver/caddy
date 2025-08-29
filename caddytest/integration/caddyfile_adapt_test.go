package integration

import (
	jsonMod "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddytest"
	_ "github.com/caddyserver/caddy/v2/internal/testmocks"
)

func TestCaddyfileAdaptToJSON(t *testing.T) {
	// load the list of test files from the dir
	files, err := os.ReadDir("./caddyfile_adapt")
	if err != nil {
		t.Errorf("failed to read caddyfile_adapt dir: %s", err)
	}

	// prep a regexp to fix strings on windows
	winNewlines := regexp.MustCompile(`\r?\n`)

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		filename := f.Name()

		// run each file as a subtest, so that we can see which one fails more easily
		t.Run(filename, func(t *testing.T) {
			// read the test file
			data, err := os.ReadFile("./caddyfile_adapt/" + filename)
			if err != nil {
				t.Errorf("failed to read %s dir: %s", filename, err)
			}

			// split the Caddyfile (first) and JSON (second) parts
			// (append newline to Caddyfile to match formatter expectations)
			parts := strings.Split(string(data), "----------")
			caddyfile, expected := strings.TrimSpace(parts[0])+"\n", strings.TrimSpace(parts[1])

			// replace windows newlines in the json with unix newlines
			expected = winNewlines.ReplaceAllString(expected, "\n")

			// replace os-specific default path for file_server's hide field
			replacePath, _ := jsonMod.Marshal(fmt.Sprint(".", string(filepath.Separator), "Caddyfile"))
			expected = strings.ReplaceAll(expected, `"./Caddyfile"`, string(replacePath))

			// if the expected output is JSON, compare it
			if len(expected) > 0 && expected[0] == '{' {
				ok := caddytest.CompareAdapt(t, filename, caddyfile, "caddyfile", expected)
				if !ok {
					t.Errorf("failed to adapt %s", filename)
				}
				return
			}

			// otherwise, adapt the Caddyfile and check for errors
			cfgAdapter := caddyconfig.GetAdapter("caddyfile")
			_, _, err = cfgAdapter.Adapt([]byte(caddyfile), nil)
			if err == nil {
				t.Errorf("expected error for %s but got none", filename)
			} else {
				normalizedErr := winNewlines.ReplaceAllString(err.Error(), "\n")
				if !strings.Contains(normalizedErr, expected) {
					t.Errorf("expected error for %s to contain:\n%s\nbut got:\n%s", filename, expected, normalizedErr)
				}
			}
		})
	}
}
