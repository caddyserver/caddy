package integration

import (
	"io/ioutil"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileAdaptToJSON(t *testing.T) {
	// load the list of test files from the dir
	files, err := ioutil.ReadDir("./caddyfile_adapt")
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
		data, err := ioutil.ReadFile("./caddyfile_adapt/" + filename)
		if err != nil {
			t.Errorf("failed to read %s dir: %s", filename, err)
		}

		// split the Caddyfile (first) and JSON (second) parts
		parts := strings.Split(string(data), "----------")
		caddyfile, json := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		// replace windows newlines in the json with unix newlines
		json = winNewlines.ReplaceAllString(json, "\n")

		// run the test
		ok := caddytest.CompareAdapt(t, caddyfile, "caddyfile", json)
		if !ok {
			t.Errorf("failed to adapt %s", filename)
		}
	}
}
