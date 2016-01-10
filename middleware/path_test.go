package middleware

import "testing"

func TestConfigPath(t *testing.T) {
	testRules := ConfigPaths{
		testPath("/"),
		testPath("/school"),
		testPath("/s"),
		testPath("/sch"),
		testPath("/schools"),
	}

	rules := ConfigPaths{}
	for _, r := range testRules {
		rules.Add(r)
	}

	expected := []string{
		"/schools", "/school", "/sch", "/s", "/",
	}

	for i, r := range rules {
		if r.Path() != expected[i] {
			t.Errorf("Expected %v at index %d found %v", expected[i], i, r.Path())
		}
	}

}

type testPath string

func (t testPath) Path() string {
	return string(t)
}
