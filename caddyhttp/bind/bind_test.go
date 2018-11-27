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

package bind

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetupBind(t *testing.T) {
	for _, testcase := range []struct {
		Bind    string
		Hosts   []string
		TLSHost string
	}{
		{
			Bind:    "bind 1.2.3.4",
			Hosts:   []string{"1.2.3.4"},
			TLSHost: "1.2.3.4",
		},
		{
			Bind:    "bind 1.2.3.4 5.6.7.8",
			Hosts:   []string{"1.2.3.4", "5.6.7.8"},
			TLSHost: "1.2.3.4",
		},
	} {
		c := caddy.NewTestController("http", testcase.Bind)
		err := setupBind(c)
		if err != nil {
			t.Fatalf("Expected no errors, but got: %v", err)
		}

		cfg := httpserver.GetConfig(c)
		if got, want := cfg.ListenHosts, testcase.Hosts; !reflect.DeepEqual(got, want) {
			t.Errorf("Expected the config's ListenHost to be %s, was %s", want, got)
		}
		if got, want := cfg.TLS.ListenHost, testcase.TLSHost; got != want {
			t.Errorf("Expected the TLS config's ListenHost to be %s, was %s", want, got)
		}
	}
}
