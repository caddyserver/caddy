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

package caddyscript

import (
	"fmt"
	ti "time"

	"go.starlark.net/starlark"
)

// Time represents a time type for caddyscript.
type Time struct {
	value int64 // time since epoch in nanoseconds
}

// AttrNames defines what properties and methods are available on the Time type.
func (r Time) AttrNames() []string {
	return []string{"now", "parse", "add", "subtract", "minute", "hour", "day", "value"}
}

// Attr defines what happens when props or methods are called on the Time type.
func (r Time) Attr(name string) (starlark.Value, error) {
	switch name {
	case "now":
		b := starlark.NewBuiltin("now", r.Now)
		b = b.BindReceiver(r)
		return b, nil
	case "parse_duration":
		b := starlark.NewBuiltin("parse_duration", r.ParseDuration)
		b = b.BindReceiver(r)
		return b, nil
	case "add":
		b := starlark.NewBuiltin("add", r.Add)
		b = b.BindReceiver(r)
		return b, nil
	case "subtract":
		b := starlark.NewBuiltin("subtract", r.Subtract)
		b = b.BindReceiver(r)
		return b, nil
	case "minute":
		b := starlark.NewBuiltin("minute", r.Minute)
		b = b.BindReceiver(r)
		return b, nil
	case "hour":
		b := starlark.NewBuiltin("hour", r.Hour)
		b = b.BindReceiver(r)
		return b, nil
	case "day":
		b := starlark.NewBuiltin("day", r.Day)
		b = b.BindReceiver(r)
		return b, nil
	case "value":
		return starlark.MakeInt64(r.value), nil
	}

	return nil, nil
}

func (r Time) Freeze()               {}
func (r Time) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: Time") }
func (r Time) String() string        { return fmt.Sprint(r.value) }
func (r Time) Type() string          { return "Time" }
func (r Time) Truth() starlark.Bool  { return true }

// Hour returns the current hour of a unix timestamp in range [0, 23].
func (r Time) Hour(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	t := ti.Unix(0, r.value)
	return starlark.MakeInt(t.Hour()), nil
}

// Minute returns the current minute of the hour for a unix timestamp in range [0, 59].
func (r Time) Minute(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	t := ti.Unix(0, r.value)
	return starlark.MakeInt(t.Minute()), nil
}

// Day returns the current day in a week of a unix timestamp... [Sunday = 0...]
func (r Time) Day(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	t := ti.Unix(0, r.value)
	return starlark.MakeInt(int(t.Weekday())), nil
}

// Now returns the current time as a unix timestamp.
func (r Time) Now(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	val := ti.Now().UnixNano()
	r.value = val
	return r, nil
}

// ParseDuration parses a go duration string to a time type.
func (r Time) ParseDuration(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dur string
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &dur)
	if err != nil {
		return starlark.None, fmt.Errorf("could not unpack args: %v", err.Error())
	}

	if parsed, err := ti.ParseDuration(dur); err == nil {
		val := parsed.Nanoseconds()
		r.value = val
		return r, nil
	}

	return starlark.None, fmt.Errorf("time.parse_duration: argument cannot be parsed as a valid go time duration")
}

// Add adds time to a time type.
func (r Time) Add(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var t Time
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &t)
	if err != nil {
		return starlark.None, fmt.Errorf("could not unpack args: %v", err.Error())
	}

	val := r.value + t.value
	r.value = val
	return r, nil
}

// Subtract adds time to a time type.
func (r Time) Subtract(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var t Time
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &t)
	if err != nil {
		return starlark.None, fmt.Errorf("could not unpack args: %v", err.Error())
	}

	val := r.value - t.value
	r.value = val
	return r, nil
}
