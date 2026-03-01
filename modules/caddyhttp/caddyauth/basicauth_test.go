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

package caddyauth

import (
	"encoding/base64"
	"testing"
)

func TestParseBasicAuth(t *testing.T) {
	type basicAuthTest struct {
		username string
		password string
		ok       bool
	}
	testCases := []struct {
		name   string
		header string
		want   basicAuthTest
	}{
		{
			name:   "Empty header",
			header: "",
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Valid header",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "Aladdin",
				password: "open sesame",
				ok:       true,
			},
		},
		{
			name:   "Upper case scheme",
			header: "BASIC " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "Aladdin",
				password: "open sesame",
				ok:       true,
			},
		},
		{
			name:   "Lower case scheme",
			header: "basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "Aladdin",
				password: "open sesame",
				ok:       true,
			},
		},
		{
			name:   "Mixed case scheme",
			header: "BaSiC " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "Aladdin",
				password: "open sesame",
				ok:       true,
			},
		},
		{
			name:   "Password with colon",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open:sesame")),
			want: basicAuthTest{
				username: "Aladdin",
				password: "open:sesame",
				ok:       true,
			},
		},
		{
			name:   "Empty username and password",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       true,
			},
		},
		{
			name:   "Missing password",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin")),
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Empty username",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte(":open sesame")),
			want: basicAuthTest{
				username: "",
				password: "open sesame",
				ok:       true,
			},
		},
		{
			name:   "Missing space between scheme and credentials",
			header: "Basic" + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Multiple spaces between scheme and credentials",
			header: "Basic  " + base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Missing scheme",
			header: base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")),
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Missing credentials",
			header: "Basic ",
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Credentials are not base64-encoded",
			header: "Basic Aladdin:open sesame",
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
		{
			name:   "Invalid scheme",
			header: `Digest username="Aladdin"`,
			want: basicAuthTest{
				username: "",
				password: "",
				ok:       false,
			},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(*testing.T) {
			username, password, ok := parseBasicAuth(tt.header)
			actual := basicAuthTest{username, password, ok}
			if tt.want != actual {
				t.Errorf("BasicAuth() = %#v, want %#v", actual, tt.want)
			}
		})
	}
}
