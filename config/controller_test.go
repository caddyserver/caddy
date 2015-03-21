package config

import "testing"

func TestController(t *testing.T) {
	c := controller{parser: new(parser)}

	c.Startup(func() error { return nil })
	if n := len(c.parser.cfg.Startup); n != 1 {
		t.Errorf("Expected length of startup functions to be 1, got %d", n)
	}

	if root := c.Root(); root != "." {
		t.Errorf("Expected defualt root path to be '.', got '%s'", root)
	}

	c.parser.cfg.Root = "foobar/test"
	if root := c.Root(); root != c.parser.cfg.Root {
		t.Errorf("Expected established root path to be '%s', got '%s'", c.parser.cfg.Root, root)
	}

	c.parser.cfg.Host = "localhost"
	if host := c.Host(); host != c.parser.cfg.Host {
		t.Errorf("Expected host to be '%s', got '%s'", c.parser.cfg.Host, host)
	}

	c.parser.cfg.Port = "1234"
	if port := c.Port(); port != c.parser.cfg.Port {
		t.Errorf("Expected port to be '%s', got '%s'", c.parser.cfg.Port, port)
	}

	c.pathScope = "unused"
	if context := c.Context(); string(context) != c.pathScope {
		t.Errorf("Expected context to be '%s', got '%s'", c.pathScope, context)
	}
}
