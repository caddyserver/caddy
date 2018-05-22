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

package compress

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `compress`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if mids == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Compress)
	if !ok {
		t.Fatalf("Expected handler to be type Compress, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`compress`, false},
		{`compress zstd`, false},
		{`compress foo`, true},
		{`compress gzip`, false},
		{`compress gzip {`, true},
		{`compress gzip {}`, true},
		{`compress {}`, true},
		{`compress gzip a b`, true},
		{`compress gzip a {`, true},
		{`compress gzip { not f } `, true},
		{`compress gzip { not } `, true},
		{`compress gzip { not /file
		 ext .html
		 level 1
		} `, false},
		{`compress gzip { level 9 } `, false},
		{`compress zstd { level 9 } `, false},
		{`compress { level 9 } `, true},
		{`compress gzip { ext } `, true},
		{`compress gzip { ext /f
		} `, true},
		{`compress gzip { not /file
		 ext .html
		 level 1
		}
		compress gzip`, false},
		{`compress gzip {
		 ext ""
		}`, false},
		{`compress gzip { not /file
		 ext .html
		 level 1
		}
		compress gzip { not /file1
		 ext .htm
		 level 3
		}
		`, false},
		{`compress gzip { not /file
		 ext .html
		 level 1
		}
		compress gzip { not /file1
		 ext .htm
		 level 3
		}
		`, false},
		{`compress gzip { not /file
		 ext *
		 level 1
		}
		`, false},
		{`compress gzip { not /file
		 ext *
		 level 1
		 min_length ab
		}
		`, true},
		{`compress gzip { not /file
		 ext *
		 level 1
		 min_length 1000
		}
		`, false},
	}
	for i, test := range tests {
		_, err := compressParse(caddy.NewTestController("http", test.input))
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}

func TestShouldAddResponseFilters(t *testing.T) {
	configs, err := compressParse(caddy.NewTestController("http", `compress gzip { min_length 654 }`))

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
