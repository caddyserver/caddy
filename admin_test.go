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
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"
)

var testCfg = []byte(`{
			"apps": {
				"http": {
					"servers": {
						"myserver": {
							"listen": ["tcp/localhost:8080-8084"],
							"read_timeout": "30s"
						},
						"yourserver": {
							"listen": ["127.0.0.1:5000"],
							"read_header_timeout": "15s"
						}
					}
				}
			}
		}
		`)

func TestUnsyncedConfigAccess(t *testing.T) {
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
			method:    "DELETE",
			path:      "/bar/qq",
			expect:    `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c"]}`,
			shouldErr: true,
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
		{
			method:  "POST",
			path:    "/list/...",
			payload: `["e", "f", "g"]`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d", "e", "f", "g"]}`,
		},
	} {
		err := unsyncedConfigAccess(tc.method, rawConfigKey+tc.path, []byte(tc.payload), nil)

		if tc.shouldErr && err == nil {
			t.Fatalf("Test %d: Expected error return value, but got: %v", i, err)
		}
		if !tc.shouldErr && err != nil {
			t.Fatalf("Test %d: Should not have had error return value, but got: %v", i, err)
		}

		// decode the expected config so we can do a convenient DeepEqual
		var expectedDecoded any
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

// TestLoadConcurrent exercises Load under concurrent conditions
// and is most useful under test with `-race` enabled.
func TestLoadConcurrent(t *testing.T) {
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			_ = Load(testCfg, true)
			wg.Done()
		}()
	}
	wg.Wait()
}

type fooModule struct {
	IntField int
	StrField string
}

func (fooModule) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "foo",
		New: func() Module { return new(fooModule) },
	}
}
func (fooModule) Start() error { return nil }
func (fooModule) Stop() error  { return nil }

func TestETags(t *testing.T) {
	RegisterModule(fooModule{})

	if err := Load([]byte(`{"admin": {"listen": "localhost:2999"}, "apps": {"foo": {"strField": "abc", "intField": 0}}}`), true); err != nil {
		t.Fatalf("loading: %s", err)
	}

	const key = "/" + rawConfigKey + "/apps/foo"

	// try update the config with the wrong etag
	err := changeConfig(http.MethodPost, key, []byte(`{"strField": "abc", "intField": 1}}`), fmt.Sprintf(`"/%s not_an_etag"`, rawConfigKey), false)
	if apiErr, ok := err.(APIError); !ok || apiErr.HTTPStatus != http.StatusPreconditionFailed {
		t.Fatalf("expected precondition failed; got %v", err)
	}

	// get the etag
	hash := etagHasher()
	if err := readConfig(key, hash); err != nil {
		t.Fatalf("reading: %s", err)
	}

	// do the same update with the correct key
	err = changeConfig(http.MethodPost, key, []byte(`{"strField": "abc", "intField": 1}`), makeEtag(key, hash), false)
	if err != nil {
		t.Fatalf("expected update to work; got %v", err)
	}

	// now try another update. The hash should no longer match and we should get precondition failed
	err = changeConfig(http.MethodPost, key, []byte(`{"strField": "abc", "intField": 2}`), makeEtag(key, hash), false)
	if apiErr, ok := err.(APIError); !ok || apiErr.HTTPStatus != http.StatusPreconditionFailed {
		t.Fatalf("expected precondition failed; got %v", err)
	}
}

func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Load(testCfg, true)
	}
}
