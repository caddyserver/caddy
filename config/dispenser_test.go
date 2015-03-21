package config

import (
	"strings"
	"testing"
)

func TestDispenser_cursor_Val_Next(t *testing.T) {
	input := `host:port
			  dir1 arg1
			  dir2 arg2 arg3
			  dir3`
	d := mockDispenser("test", input)

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
	d := mockDispenser("test", input)

	assertNext := func(shouldLoad bool, expectedVal string) {
		if d.Next() != shouldLoad {
			t.Errorf("Next(): Should load token but got false instead (val: '%s')", d.Val())
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
	}

	assertNextArg := func(expectedVal string, loadAnother bool) {
		if d.NextArg() != true {
			t.Error("NextArg(): Should load next argument but got false instead")
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
		if !loadAnother {
			if d.NextArg() != false {
				t.Fatalf("NextArg(): Should NOT load another argument, but got true instead (val: '%s')", d.Val())
			}
		}
	}

	assertNext(true, "dir1")
	assertNextArg("arg1", false)
	assertNext(true, "dir2")
	assertNextArg("arg2", true)
	assertNextArg("arg3", false)
	assertNext(true, "dir3")
	assertNext(false, "dir3")
}

func TestDispenser_NextLine(t *testing.T) {
	input := `host:port
			  dir1 arg1
			  dir2 arg2 arg3`
	d := mockDispenser("test", input)

	assertNextLine := func(shouldLoad bool, expectedVal string) {
		if d.NextLine() != shouldLoad {
			t.Errorf("NextLine(): Should load token but got false instead (val: '%s')", d.Val())
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
	}

	assertNextLine(true, "host:port")
	assertNextLine(true, "dir1")
	assertNextLine(false, "dir1")
	d.Next() // arg1
	assertNextLine(true, "dir2")
	assertNextLine(false, "dir2")
	d.Next() // arg2
	assertNextLine(false, "arg2")
	d.Next() // arg3
	assertNextLine(false, "arg3")
}

func TestDispenser_NextBlock_nesting(t *testing.T) {
	/*input := `foobar1 {
			  	sub1 arg1 arg2 arg3
			  	sub2 arg2
			  	sub3
			  }
			  foobar2 {
			  }
			  foobar3`
	d := mockDispenser("test", input)
	*/
	// TODO
}

func mockDispenser(filename, input string) dispenser {
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
