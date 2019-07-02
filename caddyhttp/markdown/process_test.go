// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package markdown

import (
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
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
