package integration

import (
	jsonMod "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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

		// read the test file
		filename := f.Name()
		data, err := os.ReadFile("./caddyfile_adapt/" + filename)
		if err != nil {
			t.Errorf("failed to read %s dir: %s", filename, err)
		}

		// split the Caddyfile (first) and JSON (second) parts
		// (append newline to Caddyfile to match formatter expectations)
		parts := strings.Split(string(data), "----------")
		caddyfile, json := strings.TrimSpace(parts[0])+"\n", strings.TrimSpace(parts[1])

		// replace windows newlines in the json with unix newlines
		json = winNewlines.ReplaceAllString(json, "\n")

		// replace os-specific default path for file_server's hide field
		replacePath, _ := jsonMod.Marshal(fmt.Sprint(".", string(filepath.Separator), "Caddyfile"))
		json = strings.ReplaceAll(json, `"./Caddyfile"`, string(replacePath))

		// run the test
		ok := caddytest.CompareAdapt(t, filename, caddyfile, "caddyfile", json)
		if !ok {
			t.Errorf("failed to adapt %s", filename)
		}
	}
}
