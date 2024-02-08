// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyfile

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDispenser_Val_Next(t *testing.T) {
	input := `host:port
			  dir1 arg1
			  dir2 arg2 arg3
			  dir3`
	d := NewTestDispenser(input)

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
	d := NewTestDispenser(input)

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
		if !d.NextArg() {
			t.Error("NextArg(): Should load next argument but got false instead")
		}
		if d.cursor != expectedCursor {
			t.Errorf("NextArg(): Expected cursor to be at %d, but it was %d", expectedCursor, d.cursor)
		}
		if val := d.Val(); val != expectedVal {
			t.Errorf("Val(): Expected '%s' but got '%s'", expectedVal, val)
		}
		if !loadAnother {
			if d.NextArg() {
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
	d := NewTestDispenser(input)

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
	d := NewTestDispenser(input)

	assertNextBlock := func(shouldLoad bool, expectedCursor, expectedNesting int) {
		if loaded := d.NextBlock(0); loaded != shouldLoad {
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
	d.Next()                     // foobar2
	assertNextBlock(false, 8, 0) // empty block is as if it didn't exist
}

func TestDispenser_Args(t *testing.T) {
	var s1, s2, s3 string
	input := `dir1 arg1 arg2 arg3
			  dir2 arg4 arg5
			  dir3 arg6 arg7
			  dir4`
	d := NewTestDispenser(input)

	d.Next() // dir1

	// As many strings as arguments
	if all := d.Args(&s1, &s2, &s3); !all {
		t.Error("Args(): Expected true, got false")
	}
	if s1 != "arg1" {
		t.Errorf("Args(): Expected s1 to be 'arg1', got '%s'", s1)
	}
	if s2 != "arg2" {
		t.Errorf("Args(): Expected s2 to be 'arg2', got '%s'", s2)
	}
	if s3 != "arg3" {
		t.Errorf("Args(): Expected s3 to be 'arg3', got '%s'", s3)
	}

	d.Next() // dir2

	// More strings than arguments
	if all := d.Args(&s1, &s2, &s3); all {
		t.Error("Args(): Expected false, got true")
	}
	if s1 != "arg4" {
		t.Errorf("Args(): Expected s1 to be 'arg4', got '%s'", s1)
	}
	if s2 != "arg5" {
		t.Errorf("Args(): Expected s2 to be 'arg5', got '%s'", s2)
	}
	if s3 != "arg3" {
		t.Errorf("Args(): Expected s3 to be unchanged ('arg3'), instead got '%s'", s3)
	}

	// (quick cursor check just for kicks and giggles)
	if d.cursor != 6 {
		t.Errorf("Cursor should be 6, but is %d", d.cursor)
	}

	d.Next() // dir3

	// More arguments than strings
	if all := d.Args(&s1); !all {
		t.Error("Args(): Expected true, got false")
	}
	if s1 != "arg6" {
		t.Errorf("Args(): Expected s1 to be 'arg6', got '%s'", s1)
	}

	d.Next() // dir4

	// No arguments or strings
	if all := d.Args(); !all {
		t.Error("Args(): Expected true, got false")
	}

	// No arguments but at least one string
	if all := d.Args(&s1); all {
		t.Error("Args(): Expected false, got true")
	}
}

func TestDispenser_RemainingArgs(t *testing.T) {
	input := `dir1 arg1 arg2 arg3
			  dir2 arg4 arg5
			  dir3 arg6 { arg7
			  dir4`
	d := NewTestDispenser(input)

	d.Next() // dir1

	args := d.RemainingArgs()
	if expected := []string{"arg1", "arg2", "arg3"}; !reflect.DeepEqual(args, expected) {
		t.Errorf("RemainingArgs(): Expected %v, got %v", expected, args)
	}

	d.Next() // dir2

	args = d.RemainingArgs()
	if expected := []string{"arg4", "arg5"}; !reflect.DeepEqual(args, expected) {
		t.Errorf("RemainingArgs(): Expected %v, got %v", expected, args)
	}

	d.Next() // dir3

	args = d.RemainingArgs()
	if expected := []string{"arg6"}; !reflect.DeepEqual(args, expected) {
		t.Errorf("RemainingArgs(): Expected %v, got %v", expected, args)
	}

	d.Next() // {
	d.Next() // arg7
	d.Next() // dir4

	args = d.RemainingArgs()
	if len(args) != 0 {
		t.Errorf("RemainingArgs(): Expected %v, got %v", []string{}, args)
	}
}

func TestDispenser_ArgErr_Err(t *testing.T) {
	input := `dir1 {
			  }
			  dir2 arg1 arg2`
	d := NewTestDispenser(input)

	d.cursor = 1 // {

	if err := d.ArgErr(); err == nil || !strings.Contains(err.Error(), "{") {
		t.Errorf("ArgErr(): Expected an error message with { in it, but got '%v'", err)
	}

	d.cursor = 5 // arg2

	if err := d.ArgErr(); err == nil || !strings.Contains(err.Error(), "arg2") {
		t.Errorf("ArgErr(): Expected an error message with 'arg2' in it; got '%v'", err)
	}

	err := d.Err("foobar")
	if err == nil {
		t.Fatalf("Err(): Expected an error, got nil")
	}

	if !strings.Contains(err.Error(), "Testfile:3") {
		t.Errorf("Expected error message with filename:line in it; got '%v'", err)
	}

	if !strings.Contains(err.Error(), "foobar") {
		t.Errorf("Expected error message with custom message in it ('foobar'); got '%v'", err)
	}

	ErrBarIsFull := errors.New("bar is full")
	bookingError := d.Errf("unable to reserve: %w", ErrBarIsFull)
	if !errors.Is(bookingError, ErrBarIsFull) {
		t.Errorf("Errf(): should be able to unwrap the error chain")
	}
}
