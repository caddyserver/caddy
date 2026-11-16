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
	"net"
	"net/url"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal"
)

func TestPrivacyFiltersTypedValues(t *testing.T) {
	const value = "192.0.2.99"
	re := &RegexpFilter{RawRegexp: `192[.]0[.]2[.]99`, Value: "REDACTED"}
	multi := &MultiRegexpFilter{}
	if err := multi.AddOperation(`192[.]0[.]2[.]99`, "REDACTED"); err != nil {
		t.Fatal(err)
	}
	mask := &IPMaskFilter{IPv4MaskRaw: 24, IPv6MaskRaw: 32}
	for _, p := range []caddy.Provisioner{re, multi, mask} {
		if err := p.Provision(caddy.Context{}); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name   string
		filter LogFieldFilter
		want   string
	}{
		{"regexp", re, "REDACTED"},
		{"multi_regexp", multi, "REDACTED"},
		{"ip_mask", mask, "192.0.2.0"},
		{"hash", &HashFilter{}, hash(value)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strings := []string{value}
			ips := []net.IP{net.ParseIP(value)}
			originalIP := append(net.IP(nil), ips[0]...)
			uris := []*url.URL{{Path: value}}
			for _, input := range []struct {
				name  string
				field zapcore.Field
				array bool
			}{
				{"scalar", zap.Any("private", value), false},
				{"ip", zap.Any("private", ips[0]), false},
				{"strings", zap.Any("private", strings), true},
				{"reflected_strings", zap.Reflect("private", strings), true},
				{"ips", zap.Any("private", ips), true},
				{"uris", zap.Any("private", uris), true},
				{"wrapper", zap.Array("private", internal.LoggableStringArray(strings)), true},
				{"empty", zap.Any("private", []string{}), true},
			} {
				t.Run(input.name, func(t *testing.T) {
					enc := FilterEncoder{
						wrapped: zapcore.NewJSONEncoder(zapcore.EncoderConfig{}),
						Fields:  map[string]LogFieldFilter{"private": tc.filter},
					}
					buf, err := enc.EncodeEntry(zapcore.Entry{}, []zapcore.Field{input.field})
					if err != nil {
						t.Fatal(err)
					}
					defer buf.Free()
					var got map[string]any
					if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					var want any = tc.want
					if input.array {
						want = []any{tc.want}
					}
					if input.name == "empty" {
						want = []any{}
					}
					if !reflect.DeepEqual(got["private"], want) {
						t.Fatalf("encoded %s, want private=%v", buf.String(), want)
					}
				})
			}
			if strings[0] != value || !reflect.DeepEqual(ips[0], originalIP) || uris[0].Path != value {
				t.Fatal("filter mutated source certificate values")
			}
		})
	}
}
