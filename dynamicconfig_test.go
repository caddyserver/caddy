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

package caddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestMutateConfig(t *testing.T) {
	// each test is performed in sequence, so
	// each change builds on the previous ones;
	// the config is not reset between tests
	for i, tc := range []struct {
		method    string
		path      string // rawConfigKey will be prepended
		payload   string
		expect    string // JSON representation of what the whole config is expected to be after the request
		shouldErr bool
	}{
		{
			method:  "POST",
			path:    "",
			payload: `{"foo": "bar", "list": ["a", "b", "c"]}`, // starting value
			expect:  `{"foo": "bar", "list": ["a", "b", "c"]}`,
		},
		{
			method:  "POST",
			path:    "/foo",
			payload: `"jet"`,
			expect:  `{"foo": "jet", "list": ["a", "b", "c"]}`,
		},
		{
			method:  "POST",
			path:    "/bar",
			payload: `{"aa": "bb", "qq": "zz"}`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb", "qq": "zz"}, "list": ["a", "b", "c"]}`,
		},
		{
			method: "DELETE",
			path:   "/bar/qq",
			expect: `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c"]}`,
		},
		{
			method:  "POST",
			path:    "/list",
			payload: `"e"`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "e"]}`,
		},
		{
			method:  "PUT",
			path:    "/list/3",
			payload: `"d"`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d", "e"]}`,
		},
		{
			method: "DELETE",
			path:   "/list/3",
			expect: `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "e"]}`,
		},
		{
			method:  "PATCH",
			path:    "/list/3",
			payload: `"d"`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d"]}`,
		},
	} {
		req, err := http.NewRequest(tc.method, rawConfigKey+tc.path, strings.NewReader(tc.payload))
		if err != nil {
			t.Fatalf("Test %d: making test request: %v", i, err)
		}
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		err = mutateConfig(w, req)

		if tc.shouldErr && err == nil {
			t.Fatalf("Test %d: Expected error return value, but got: %v", i, err)
		}
		if !tc.shouldErr && err != nil {
			t.Fatalf("Test %d: Should not have had error return value, but got: %v", i, err)
		}

		if tc.shouldErr && w.Code == http.StatusOK {
			t.Fatalf("Test %d: Expected error, but got HTTP %d: %s",
				i, w.Code, w.Body.String())
		}
		if !tc.shouldErr && w.Code != http.StatusOK {
			t.Fatalf("Test %d: Should not have errored, but got HTTP %d: %s",
				i, w.Code, w.Body.String())
		}

		// decode the expected config so we can do a convenient DeepEqual
		var expectedDecoded interface{}
		err = json.Unmarshal([]byte(tc.expect), &expectedDecoded)
		if err != nil {
			t.Fatalf("Test %d: Unmarshaling expected config: %v", i, err)
		}

		// make sure the resulting config is as we expect it
		if !reflect.DeepEqual(rawCfg[rawConfigKey], expectedDecoded) {
			t.Fatalf("Test %d:\nExpected:\n\t%#v\nActual:\n\t%#v",
				i, expectedDecoded, rawCfg[rawConfigKey])
		}
	}
}
