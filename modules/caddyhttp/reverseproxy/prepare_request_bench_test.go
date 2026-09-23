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

package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func BenchmarkPrepareRequest(b *testing.B) {
	h := Handler{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "1.2.3.4",
	}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))

	repl := caddy.NewReplacer()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.prepareRequest(req, repl); err != nil {
			b.Fatal(err)
		}
	}
}
