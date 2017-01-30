package markdown

import (
	"os"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestConfig_Markdown(t *testing.T) {
	tests := []map[string]string{
		{"author": "authorVal"},
		{"copyright": "copyrightVal"},
		{"description": "descriptionVal"},
		{"subject": "subjectVal"},
		{"author": "authorVal", "copyright": "copyrightVal"},
		{"author": "authorVal", "copyright": "copyrightVal", "description": "descriptionVal"},
		{"author": "authorVal", "copyright": "copyrightVal", "description": "descriptionVal", "subject": "subjectVal"},
	}

	for i, meta := range tests {
		config := &Config{
			Template: GetDefaultTemplate(),
		}

		toml := "+++"
		for key, val := range meta {
			toml = toml + "\n" + key + "= \"" + val + "\""
		}
		toml = toml + "\n+++"

		res, _ := config.Markdown("Test title", strings.NewReader(toml), []os.FileInfo{}, httpserver.Context{})
		sRes := string(res)

		for key, val := range meta {
			c := strings.Contains(sRes, "<meta name=\""+key+"\" content=\""+val+"\">")
			if !c {
				t.Error("Test case", i, "should contain meta", key, val)
			}
		}
	}
}
