package caddyscript

import (
	"fmt"
	"regexp"

	"go.starlark.net/starlark"
)

// Regexp represents a regexp type for caddyscript.
type Regexp struct{}

// AttrNames defines what properties and methods are available on the Time type.
func (r Regexp) AttrNames() []string {
	return []string{"match_string"}
}

// Attr defines what happens when props or methods are called on the Time type.
func (r Regexp) Attr(name string) (starlark.Value, error) {
	switch name {
	case "match_string":
		b := starlark.NewBuiltin("match_string", r.MatchString)
		b = b.BindReceiver(r)
		return b, nil
	}

	return nil, nil
}

// MatchString reports whether the string s contains any match of the regular expression pattern. More complicated queries need to use Compile and the full Regexp interface.
func (r Regexp) MatchString(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, match string
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &pattern, &match)
	if err != nil {
		return starlark.None, fmt.Errorf("could not unpack args: %v", err.Error())
	}

	matched, err := regexp.MatchString(pattern, match)
	if err != nil {
		return starlark.False, fmt.Errorf("matchstring: %v", err.Error())
	}

	return starlark.Bool(matched), nil
}

func (r Regexp) Freeze()               {}
func (r Regexp) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: Regexp") }
func (r Regexp) String() string        { return fmt.Sprint(r) }
func (r Regexp) Type() string          { return "Regexp" }
func (r Regexp) Truth() starlark.Bool  { return true }
