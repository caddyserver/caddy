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

package gzip

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `gzip`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if mids == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Gzip)
	if !ok {
		t.Fatalf("Expected handler to be type Gzip, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`gzip {`, true},
		{`gzip {}`, true},
		{`gzip a b`, true},
		{`gzip a {`, true},
		{`gzip { not f } `, true},
		{`gzip { not } `, true},
		{`gzip { not /file
		 ext .html
		 level 1
		} `, false},
		{`gzip { level 9 } `, false},
		{`gzip { ext } `, true},
		{`gzip { ext /f
		} `, true},
		{`gzip { not /file
		 ext .html
		 level 1
		}
		gzip`, false},
		{`gzip {
		 ext ""
		}`, false},
		{`gzip { not /file
		 ext .html
		 level 1
		}
		gzip { not /file1
		 ext .htm
		 level 3
		}
		`, false},
		{`gzip { not /file
		 ext .html
		 level 1
		}
		gzip { not /file1
		 ext .htm
		 level 3
		}
		`, false},
		{`gzip { not /file
		 ext *
		 level 1
		}
		`, false},
		{`gzip { not /file
		 ext *
		 level 1
		 min_length ab
		}
		`, true},
		{`gzip { not /file
		 ext *
		 level 1
		 min_length 1000
		}
		`, false},
	}
	for i, test := range tests {
		_, err := gzipParse(caddy.NewTestController("http", test.input))
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}

func TestShouldAddResponseFilters(t *testing.T) {
	configs, err := gzipParse(caddy.NewTestController("http", `gzip { min_length 654 }`))

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
