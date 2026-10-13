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

//go:build windows

package fastcgi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On Windows the path matchers additionally fold backslashes into separators and
// trim per-component trailing dots and spaces (see caddyhttp.NormalizedPath),
// so the transport must do the same or the dot-segment bypass simply reappears
// spelled with backslashes.
func TestBuildEnvWindowsSeparatorsCannotSelectAnotherScript(t *testing.T) {
	t.Parallel()

	newRequest := func(target string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
		ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
		ctx = context.WithValue(ctx, caddyhttp.OriginalRequestCtxKey, *r)
		return r.WithContext(ctx)
	}

	for _, tc := range []struct {
		name               string
		target             string
		expectedScriptName string
		expectedPathInfo   string
	}{
		{"backslash dot segments", `/admin.php\..\other.php`, "/other.php", ""},
		{"backslash, two levels", `/admin.php\..\..\other.php`, "/other.php", ""},
		{"mixed separators", `/admin.php\../other.php`, "/other.php", ""},
		// Per-component trailing dot/space folding is Windows-only and is not
		// something CleanPath does, so this case fails unless the transport
		// applies the same normalization the matchers do.
		{"trailing dot in a path-info component", "/other.php/a./b", "/other.php", "/a/b"},
		{"trailing space in a path-info component", "/other.php/a%20/b", "/other.php", "/a/b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := Transport{Root: `C:\srv`, SplitPath: []string{".php"}}
			env, err := tr.buildEnv(newRequest(tc.target))
			require.NoError(t, err)

			assert.Equal(t, tc.expectedScriptName, env["SCRIPT_NAME"],
				"SCRIPT_NAME must come from the normalized, cleaned path")
			assert.Equal(t, tc.expectedPathInfo, env["PATH_INFO"],
				"PATH_INFO must come from the normalized, cleaned path")
			assert.NotContains(t, env["SCRIPT_FILENAME"], "admin.php",
				"a pre-normalization path component must never become the executed script")
		})
	}
}
