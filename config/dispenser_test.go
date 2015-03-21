package config

import (
	"strings"
	"testing"
)

func TestDispenser_Val_Next(t *testing.T) {
	input := `host:port
			  dir1 arg1
			  dir2 arg2 arg3
			  dir3`
	d := makeTestDispenser("test", input)

	if val := d.Val(); val != "" {
		t.Fatalf("Val(): Should return empty string when no token loaded; got '%s'", val)
	}

	assertNext := func(shouldLoad bool, expectedCursor int, expectedVal string) {
		if loaded := d.Next(); loaded != shouldLoad {
			t.Errorf("Next(): Expected %v but got %v instead (val '%s')", shouldLoad, loaded, d.Val())
		}
		if d.cursor != expectedCursor {
			t.Errorf("Expected cursor to be %d, but was %d", expectedCursor, d.cursor)
		}
		if d.nesting != 0 {
			t.Errorf("Nesting should be 0, was %d instead", d.nesting)
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
	}

	assertNext(true, 0, "host:port")
	assertNext(true, 1, "dir1")
	assertNext(true, 2, "arg1")
	assertNext(true, 3, "dir2")
	assertNext(true, 4, "arg2")
	assertNext(true, 5, "arg3")
	assertNext(true, 6, "dir3")
	// Note: This next test simply asserts existing behavior.
	// If desired, we may wish to empty the token value after
	// reading past the EOF. Open an issue if you want this change.
	assertNext(false, 6, "dir3")
}

func TestDispenser_NextArg(t *testing.T) {
	input := `dir1 arg1
			  dir2 arg2 arg3
			  dir3`
	d := makeTestDispenser("test", input)

	assertNext := func(shouldLoad bool, expectedVal string, expectedCursor int) {
		if d.Next() != shouldLoad {
			t.Errorf("Next(): Should load token but got false instead (val: '%s')", d.Val())
		}
		if d.cursor != expectedCursor {
			t.Errorf("Next(): Expected cursor to be at %d, but it was %d", expectedCursor, d.cursor)
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
	}

	assertNextArg := func(expectedVal string, loadAnother bool, expectedCursor int) {
		if d.NextArg() != true {
			t.Error("NextArg(): Should load next argument but got false instead")
		}
		if d.cursor != expectedCursor {
			t.Errorf("NextArg(): Expected cursor to be at %d, but it was %d", expectedCursor, d.cursor)
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
		if !loadAnother {
			if d.NextArg() != false {
				t.Fatalf("NextArg(): Should NOT load another argument, but got true instead (val: '%s')", d.Val())
			}
			if d.cursor != expectedCursor {
				t.Errorf("NextArg(): Expected cursor to remain at %d, but it was %d", expectedCursor, d.cursor)
			}
		}
	}

	assertNext(true, "dir1", 0)
	assertNextArg("arg1", false, 1)
	assertNext(true, "dir2", 2)
	assertNextArg("arg2", true, 3)
	assertNextArg("arg3", false, 4)
	assertNext(true, "dir3", 5)
	assertNext(false, "dir3", 5)
}

func TestDispenser_NextLine(t *testing.T) {
	input := `host:port
			  dir1 arg1
			  dir2 arg2 arg3`
	d := makeTestDispenser("test", input)

	assertNextLine := func(shouldLoad bool, expectedVal string, expectedCursor int) {
		if d.NextLine() != shouldLoad {
			t.Errorf("NextLine(): Should load token but got false instead (val: '%s')", d.Val())
		}
		if d.cursor != expectedCursor {
			t.Errorf("NextLine(): Expected cursor to be %d, instead was %d", expectedCursor, d.cursor)
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
	}

	assertNextLine(true, "host:port", 0)
	assertNextLine(true, "dir1", 1)
	assertNextLine(false, "dir1", 1)
	d.Next() // arg1
	assertNextLine(true, "dir2", 3)
	assertNextLine(false, "dir2", 3)
	d.Next() // arg2
	assertNextLine(false, "arg2", 4)
	d.Next() // arg3
	assertNextLine(false, "arg3", 5)
}

func TestDispenser_NextBlock(t *testing.T) {
	input := `foobar1 {
			  	sub1 arg1
			  	sub2
			  }
			  foobar2 {
			  }`
	d := makeTestDispenser("test", input)

	assertNextBlock := func(shouldLoad bool, expectedCursor, expectedNesting int) {
		if loaded := d.NextBlock(); loaded != shouldLoad {
			t.Errorf("NextBlock(): Should return %v but got %v", shouldLoad, loaded)
		}
		if d.cursor != expectedCursor {
			t.Errorf("NextBlock(): Expected cursor to be %d, was %d", expectedCursor, d.cursor)
		}
		if d.nesting != expectedNesting {
			t.Errorf("NextBlock(): Nesting should be %d, not %d", expectedNesting, d.nesting)
		}
	}

	assertNextBlock(false, -1, 0)
	d.Next() // foobar1
	assertNextBlock(true, 2, 1)
	assertNextBlock(true, 3, 1)
	assertNextBlock(true, 4, 1)
	assertNextBlock(false, 5, 0)
	d.Next() // foobar2
	assertNextBlock(true, 8, 1)
	assertNextBlock(false, 8, 0)
}

func makeTestDispenser(filename, input string) dispenser {
	return dispenser{
		filename: filename,
		cursor:   -1,
		tokens:   getTokens(input),
	}
}

func getTokens(input string) (tokens []token) {
	var l lexer
	l.load(strings.NewReader(input))
	for l.next() {
		tokens = append(tokens, l.token)
	}
	return
}
