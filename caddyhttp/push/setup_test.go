package push

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/mholt/caddy"
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
						i, j, actualRule.Resources, expectedRule.Resources)
				}
			}
		})
	}
}

func TestOnGo18(t *testing.T) {
	if !http2PushSupported() {
		t.Skip("Skipping test as HTTP2 Push is available on go1.8")
	}

	t.Run("ConfigParse", testConfigParse)
	t.Run("PushAvailable", testPushAvailable)
}
