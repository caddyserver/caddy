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

package brotli

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `brotli`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if mids == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Brotli)
	if !ok {
		t.Fatalf("Expected handler to be type Brotli, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`brotli {`, true},
		{`brotli {}`, true},
		{`brotli a b`, true},
		{`brotli a {`, true},
		{`brotli { not f } `, true},
		{`brotli { not } `, true},
		{`brotli { not /file
		 ext .html
		 level 1
		} `, false},
		{`brotli { level 9 } `, false},
		{`brotli { ext } `, true},
		{`brotli { ext /f
		} `, true},
		{`brotli { not /file
		 ext .html
		 level 1
		}
		brotli`, false},
		{`brotli {
		 ext ""
		}`, false},
		{`brotli { not /file
		 ext .html
		 level 1
		}
		brotli { not /file1
		 ext .htm
		 level 3
		}
		`, false},
		{`brotli { not /file
		 ext .html
		 level 1
		}
		brotli { not /file1
		 ext .htm
		 level 3
		}
		`, false},
		{`brotli { not /file
		 ext *
		 level 1
		}
		`, false},
		{`brotli { not /file
		 ext *
		 level 1
		 min_length ab
		}
		`, true},
		{`brotli { not /file
		 ext *
		 level 1
		 min_length 1000
		}
		`, false},
	}
	for i, test := range tests {
		_, err := brotliParse(caddy.NewTestController("http", test.input))
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}

func TestShouldAddResponseFilters(t *testing.T) {
	configs, err := brotliParse(caddy.NewTestController("http", `brotli { min_length 654 }`))

	if err != nil {
		t.Errorf("Test expected no error but found: %v", err)
	}
	filters := 0

	for _, config := range configs {
		for _, filter := range config.ResponseFilters {
			switch filter.(type) {
			case SkipCompressedFilter:
				filters++
			case LengthFilter:
				filters++

				if filter != LengthFilter(654) {
					t.Errorf("Expected LengthFilter to have length 654, got: %v", filter)
				}
			}
		}

		if filters != 2 {
			t.Errorf("Expected 2 response filters to be registered, got: %v", filters)
		}
	}
}
