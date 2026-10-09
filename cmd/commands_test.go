package caddycmd

import (
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal"
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

func TestCmdRun_UnbufferOnFailure(t *testing.T) {
	fs := pflag.NewFlagSet("run", pflag.ContinueOnError)
	fs.StringP("config", "c", "", "")
	fs.StringP("adapter", "a", "", "")
	fs.BoolP("resume", "r", false, "")
	fs.BoolP("environ", "e", false, "")
	fs.BoolP("watch", "w", false, "")
	fs.String("pidfile", "", "")
	fs.String("pingback", "", "")
	fs.StringSlice("envfile", nil, "")
	_ = fs.Set("config", filepath.Join(t.TempDir(), "nonexistent"))

	code, err := cmdRun(Flags{fs})
	if err == nil {
		t.Fatal("expected error from cmdRun with nonexistent config, got nil")
	}
	if code != caddy.ExitCodeFailedStartup {
		t.Errorf("expected exit code %d, got %d", caddy.ExitCodeFailedStartup, code)
	}

	// Regression test for #8180: caddy.Log() must not remain buffered after cmdRun failure
	if _, ok := caddy.Log().Core().(internal.LogBufferCoreInterface); ok {
		t.Error("caddy.Log() was left in a buffered state after cmdRun failed; should be unbuffered")
	}
}

func TestWrapCommandFuncForCobra_RunFailure(t *testing.T) {
	fs := pflag.NewFlagSet("run", pflag.ContinueOnError)
	fs.StringP("config", "c", "", "")
	fs.StringP("adapter", "a", "", "")
	fs.BoolP("resume", "r", false, "")
	fs.BoolP("environ", "e", false, "")
	fs.BoolP("watch", "w", false, "")
	fs.String("pidfile", "", "")
	fs.String("pingback", "", "")
	fs.StringSlice("envfile", nil, "")
	_ = fs.Set("config", filepath.Join(t.TempDir(), "nonexistent"))

	cmd := &cobra.Command{Use: "run"}
	cmd.Flags().AddFlagSet(fs)

	runE := WrapCommandFuncForCobra(cmdRun)
	err := runE(cmd, nil)
	if err == nil {
		t.Fatal("expected error from wrapped cmdRun, got nil")
	}

	// Regression test for #8180: caddy.Log() must not remain buffered after WrapCommandFuncForCobra
	if _, ok := caddy.Log().Core().(internal.LogBufferCoreInterface); ok {
		t.Error("caddy.Log() was left in a buffered state after WrapCommandFuncForCobra; should be unbuffered")
	}
}
