package middleware

import "testing"

func TestConfigPath(t *testing.T) {
	testRules := Configs{
		testConfig("/"),
		testConfig("/school"),
		testConfig("/s"),
		testConfig("/sch"),
		testConfig("/schools"),
	}

	rules := Configs{}
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

type testConfig string

func (t testConfig) Path() string {
	return string(t)
}
