package caddycmd

import (
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestCommandsAreAvailable(t *testing.T) {
	// trigger init, and build the default factory, so that
	// all commands from this package are available
	cmd := defaultFactory.Build()
	if cmd == nil {
		t.Fatal("default factory failed to build")
	}

	// check that the default factory has 17 commands; it doesn't
	// include the commands registered through calls to init in
	// other packages
	cmds := Commands()
	if len(cmds) != 17 {
		t.Errorf("expected 17 commands, got %d", len(cmds))
	}

	commandNames := slices.Collect(maps.Keys(cmds))
	slices.Sort(commandNames)

	expectedCommandNames := []string{
		"adapt", "add-package", "build-info", "completion",
		"environ", "fmt", "list-modules", "manpage",
		"reload", "remove-package", "run", "start",
		"stop", "storage", "upgrade", "validate", "version",
	}

	if !reflect.DeepEqual(expectedCommandNames, commandNames) {
		t.Errorf("expected %v, got %v", expectedCommandNames, commandNames)
	}
}
