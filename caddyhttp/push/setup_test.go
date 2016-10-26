package push

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestPushUnavailableOnGolangPre18(t *testing.T) {
	if !http2PushSupported() {
		err := setup(caddy.NewTestController("http", "push /index.html /index.css"))

		if err != ErrNotSupported {
			t.Fatalf("Expected setup error")
		}
	}
}

func testPushAvailable(t *testing.T) {
	err := setup(caddy.NewTestController("http", "push /index.html /available.css"))

	if err != nil {
		t.Fatalf("Error %s occured, expected none", err)
	}
}

func testConfigParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  []Rule
	}{
		{
			"ParseInvalidEmptyConfig", `push`, true, []Rule{},
		},
		{
			"ParseInvalidConfig", `push /index.html`, true, []Rule{},
		},
		{
			"ParseInvalidConfigBlock", `push /index.html /index.css {
				method
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
				Rule{
					Path: "/index.html",
					Resources: []Resource{
						Resource{
							Path:   "/style.css",
							Method: "GET",
							Header: http.Header{},
						},
						Resource{
							Path:   "/style2.css",
							Method: "GET",
							Header: http.Header{},
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
				Rule{
					Path: "/index.html",
					Resources: []Resource{
						Resource{
							Path:   "/style.css",
							Method: "HEAD",
							Header: http.Header{
								"Own-Header":  []string{"Value"},
								"Own-Header2": []string{"Value2"},
							},
						},
						Resource{
							Path:   "/style2.css",
							Method: "HEAD",
							Header: http.Header{
								"Own-Header":  []string{"Value"},
								"Own-Header2": []string{"Value2"},
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
				Rule{
					Path: "/index.html",
					Resources: []Resource{
						Resource{
							Path:   "/index.css",
							Method: "GET",
							Header: http.Header{
								"Name": []string{"value"},
							},
						},
						Resource{
							Path:   "/index2.css",
							Method: "HEAD",
							Header: http.Header{
								"Name2": []string{"value2"},
							},
						},
					},
				},
			},
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t2 *testing.T) {
			actual, err := parsePushRules(caddy.NewTestController("http", test.input))

			if err == nil && test.shouldErr {
				t2.Errorf("Test %d didn't error, but it should have", i)
			} else if err != nil && !test.shouldErr {
				t2.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
			}

			if len(actual) != len(test.expected) {
				t2.Fatalf("Test %d expected %d rules, but got %d",
					i, len(test.expected), len(actual))
			}

			for j, expectedRule := range test.expected {
				actualRule := actual[j]

				if actualRule.Path != expectedRule.Path {
					t.Errorf("Test %d, rule %d: Expected path %s, but got %s",
						i, j, expectedRule.Path, actualRule.Path)
				}

				if !reflect.DeepEqual(actualRule.Resources, expectedRule.Resources) {
					t.Errorf("Test %d, rule %d: Expected resources %v, but got %v",
						i, j, expectedRule.Resources, actualRule.Resources)
				}
			}
		})
	}
}

func testSetupInstalledMiddleware(t *testing.T) {

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

func testSetupWithError(t *testing.T) {
	// given
	c := caddy.NewTestController("http", `push /index.html`)

	// when
	err := setup(c)

	// then
	if err == nil {
		t.Error("Expected error but none occured")
	}
}

func TestOnGo18(t *testing.T) {
	if !http2PushSupported() {
		t.Skip("Skipping test as HTTP2 Push is available on go1.8")
	}

	t.Run("ConfigParse", testConfigParse)
	t.Run("PushAvailable", testPushAvailable)
	t.Run("SetupWillReturnError", testSetupWithError)
	t.Run("SetupInstalledMiddleware", testSetupInstalledMiddleware)
}
