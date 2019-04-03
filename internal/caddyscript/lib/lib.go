package caddyscript

import (
	"fmt"

	"go.starlark.net/starlark"
)

func invalidReciever(v starlark.Value, want string) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("invalid receiver: receiver set to type %v, want %v", v.Type(), want)
}
