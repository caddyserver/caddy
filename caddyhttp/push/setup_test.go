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

package push

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestPushAvailable(t *testing.T) {
	err := setup(caddy.NewTestController("http", "push /index.html /available.css"))

	if err != nil {
		t.Fatalf("Error %s occurred, expected none", err)
	}
}

func TestConfigParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  []Rule
	}{
		{
			"ParseInvalidEmptyConfig", `push`, false, []Rule{{Path: "/"}},
		},
		{
			"ParseInvalidConfig", `push /index.html`, false, []Rule{{Path: "/index.html"}},
		},
		{
			"ParseInvalidConfigBlock", `push /index.html /index.css {
				method
			}`, true, []Rule{},
		},
		{
			"ParseInvalidHeaderFormat", `push /index.html /index.css {
				header :invalid value
			}`, true, []Rule{},
		},
		{
			"ParseForbiddenHeader", `push /index.html /index.css {
				header Content-Length 1000
			}`, true, []Rule{},
		},
		{
			"ParseInvalidMethod", `push /index.html /index.css {
				method POST
			}`, true, []Rule{},
		},
		{
			"ParseInvalidHeaderBlock", `push /index.html /index.css {
				header
			}`, true, []Rule{},
		},
		{
			"ParseInvalidHeaderBlock2", `push /index.html /index.css {
				header name
			}`, true, []Rule{},
		},
		{
			"ParseProperConfig", `push /index.html /style.css /style2.css`, false, []Rule{
				{
					Path: "/index.html",
					Resources: []Resource{
						{
							Path:   "/style.css",
							Method: http.MethodGet,
							Header: http.Header{pushHeader: []string{}},
						},
						{
							Path:   "/style2.css",
							Method: http.MethodGet,
							Header: http.Header{pushHeader: []string{}},
						},
					},
				},
			},
		},
		{
			"ParseSimpleInlinePush", `push /index.html {
				/style.css
				/style2.css
			}`, false, []Rule{
				{
					Path: "/index.html",
					Resources: []Resource{
						{
							Path:   "/style.css",
							Method: http.MethodGet,
							Header: http.Header{pushHeader: []string{}},
						},
						{
							Path:   "/style2.css",
							Method: http.MethodGet,
							Header: http.Header{pushHeader: []string{}},
						},
					},
				},
			},
		},
		{
			"ParseSimpleInlinePushWithOps", `push /index.html {
				/style.css
				/style2.css
				header Test Value
			}`, false, []Rule{
				{
					Path: "/index.html",
					Resources: []Resource{
						{
							Path:   "/style.css",
							Method: http.MethodGet,
							Header: http.Header{pushHeader: []string{}, "Test": []string{"Value"}},
						},
						{
							Path:   "/style2.css",
							Method: http.MethodGet,
							Header: http.Header{pushHeader: []string{}, "Test": []string{"Value"}},
						},
					},
				},
			},
		},
		{
			"ParseProperConfigWithBlock", `push /index.html /style.css /style2.css {
				method HEAD
				header Own-Header Value
				header Own-Header2 Value2
			}`, false, []Rule{
				{
					Path: "/index.html",
					Resources: []Resource{
						{
							Path:   "/style.css",
							Method: http.MethodHead,
							Header: http.Header{
								"Own-Header":  []string{"Value"},
								"Own-Header2": []string{"Value2"},
								"X-Push":      []string{},
							},
						},
						{
							Path:   "/style2.css",
							Method: http.MethodHead,
							Header: http.Header{
								"Own-Header":  []string{"Value"},
								"Own-Header2": []string{"Value2"},
								"X-Push":      []string{},
							},
						},
					},
				},
			},
		},
		{
			"ParseMergesRules", `push /index.html /index.css {
				header name value
			}

			push /index.html /index2.css {
				header name2 value2
				method HEAD
			}
			`, false, []Rule{
				{
					Path: "/index.html",
					Resources: []Resource{
						{
							Path:   "/index.css",
							Method: http.MethodGet,
							Header: http.Header{
								"Name":   []string{"value"},
								"X-Push": []string{},
							},
						},
						{
							Path:   "/index2.css",
							Method: http.MethodHead,
							Header: http.Header{
								"Name2":  []string{"value2"},
								"X-Push": []string{},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t2 *testing.T) {
			actual, err := parsePushRules(caddy.NewTestController("http", test.input))

			if err == nil && test.shouldErr {
				t2.Errorf("Test %s didn't error, but it should have", test.name)
			} else if err != nil && !test.shouldErr {
				t2.Errorf("Test %s errored, but it shouldn't have; got '%v'", test.name, err)
			}

			if len(actual) != len(test.expected) {
				t2.Fatalf("Test %s expected %d rules, but got %d",
					test.name, len(test.expected), len(actual))
			}

			for j, expectedRule := range test.expected {
				actualRule := actual[j]

				if actualRule.Path != expectedRule.Path {
					t.Errorf("Test %s, rule %d: Expected path %s, but got %s",
						test.name, j, expectedRule.Path, actualRule.Path)
				}

				if !reflect.DeepEqual(actualRule.Resources, expectedRule.Resources) {
					t.Errorf("Test %s, rule %d: Expected resources %v, but got %v",
						test.name, j, expectedRule.Resources, actualRule.Resources)
				}
			}
		})
	}
}

func TestSetupInstalledMiddleware(t *testing.T) {

	// given
	c := caddy.NewTestController("http", `push /index.html /test.js`)

	// when
	err := setup(c)

	// then
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}

	middlewares := httpserver.GetConfig(c).Middleware()

	if len(middlewares) != 1 {
		t.Fatalf("Expected 1 middleware, had %d instead", len(middlewares))
	}

	handler := middlewares[0](httpserver.EmptyNext)
	pushHandler, ok := handler.(Middleware)

	if !ok {
		t.Fatalf("Expected handler to be type Middleware, got: %#v", handler)
	}

	if !httpserver.SameNext(pushHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler Middleware was not set properly")
	}
}

func TestSetupWithError(t *testing.T) {
	// given
	c := caddy.NewTestController("http", "push {\nmethod\n}")

	// when
	err := setup(c)

	// then
	if err == nil {
		t.Error("Expected error but none occurred")
	}
}
