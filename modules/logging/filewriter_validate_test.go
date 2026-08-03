// Copyright 2015 Matthew Holt and The Caddy Authors
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

package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestValidateDoesNotCreateLogFile ensures that validating a config
// (as `caddy validate` does) leaves no log files behind. If validation
// creates the file, running `caddy validate` as a different user than
// the server (e.g. root vs. the caddy user) leaves a file the server
// cannot open, so the subsequent reload fails with "permission denied".
// See https://github.com/caddyserver/caddy/issues/7829.
func TestValidateDoesNotCreateLogFile(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "access.log")

	cfgJSON := fmt.Sprintf(`{
		"logging": {
			"logs": {
				"log1": {
					"writer": {
						"output": "file",
						"filename": %q
					}
				}
			}
		}
	}`, logFile)

	var cfg caddy.Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshaling config: %v", err)
	}

	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("validating config: %v", err)
	}

	if _, err := os.Stat(logFile); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("validation created log file %s (stat error: %v); validating a config must not create log files", logFile, err)
	}
}
