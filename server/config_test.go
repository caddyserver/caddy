package server

import "testing"

func TestConfigAddress(t *testing.T) {
	cfg := Config{Host: "foobar", Port: "1234"}
	if actual, expected := cfg.Address(), "foobar:1234"; expected != actual {
		t.Errorf("Expected '%s' but got '%s'", expected, actual)
	}

	cfg = Config{Host: "", Port: "1234"}
	if actual, expected := cfg.Address(), ":1234"; expected != actual {
		t.Errorf("Expected '%s' but got '%s'", expected, actual)
	}

	cfg = Config{Host: "foobar", Port: ""}
	if actual, expected := cfg.Address(), "foobar:"; expected != actual {
		t.Errorf("Expected '%s' but got '%s'", expected, actual)
	}

	cfg = Config{Host: "::1", Port: "443"}
	if actual, expected := cfg.Address(), "[::1]:443"; expected != actual {
		t.Errorf("Expected '%s' but got '%s'", expected, actual)
	}
}
