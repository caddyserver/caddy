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

package caddytls

import (
	"testing"

	"github.com/mholt/certmagic"
)

type holder struct {
	host, port string
	cfg        *Config
}

func (h holder) TLSConfig() *Config { return h.cfg }
func (h holder) Host() string       { return h.host }
func (h holder) Port() string       { return h.port }

func TestQualifiesForManagedTLS(t *testing.T) {
	for i, test := range []struct {
		cfg    ConfigHolder
		expect bool
	}{
		{holder{host: ""}, false},
		{holder{host: "localhost"}, false},
		{holder{host: "123.44.3.21"}, false},
		{holder{host: "example.com"}, false},
		{holder{host: "", cfg: new(Config)}, false},
		{holder{host: "localhost", cfg: new(Config)}, false},
		{holder{host: "123.44.3.21", cfg: new(Config)}, false},
		{holder{host: "example.com", cfg: &Config{Manager: &certmagic.Config{}}}, true},
		{holder{host: "*.example.com", cfg: &Config{Manager: &certmagic.Config{}}}, true},
		{holder{host: "*.*.example.com", cfg: new(Config)}, false},
		{holder{host: "*sub.example.com", cfg: new(Config)}, false},
		{holder{host: "sub.*.example.com", cfg: new(Config)}, false},
		{holder{host: "example.com", cfg: &Config{Manager: &certmagic.Config{}, Manual: true}}, false},
		{holder{host: "example.com", cfg: &Config{Manager: &certmagic.Config{}, ACMEEmail: "off"}}, false},
		{holder{host: "example.com", cfg: &Config{Manager: &certmagic.Config{}, ACMEEmail: "foo@bar.com"}}, true},
		{holder{host: "example.com", port: "80"}, false},
		{holder{host: "example.com", port: "1234", cfg: &Config{Manager: &certmagic.Config{}}}, true},
		{holder{host: "example.com", port: "443", cfg: &Config{Manager: &certmagic.Config{}}}, true},
		{holder{host: "example.com", port: "80"}, false},
	} {
		if got, want := QualifiesForManagedTLS(test.cfg), test.expect; got != want {
			t.Errorf("Test %d: Expected %v but got %v", i, want, got)
		}
	}
}
