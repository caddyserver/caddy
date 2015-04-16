package config

import "testing"

func TestController(t *testing.T) {
	p := &parser{filename: "test"}
	c := newController(p)

	if c == nil || c.parser == nil {
		t.Fatal("Expected newController to return a non-nil controller with a non-nil parser")
	}
	if c.dispenser.cursor != -1 {
		t.Errorf("Dispenser not initialized properly; expecting cursor at -1, got %d", c.dispenser.cursor)
	}
	if c.dispenser.filename != p.filename {
		t.Errorf("Dispenser's filename should be same as parser's (%s); got '%s'", p.filename, c.dispenser.filename)
	}

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

	c.pathScope = "unused"
	if context := c.Context(); string(context) != c.pathScope {
		t.Errorf("Expected context to be '%s', got '%s'", c.pathScope, context)
	}
}
