package caddycmd

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/caddyserver/caddy/v2"
)

// newFmtFlags builds a Flags value wired up the same way the fmt cobra command does.
func newFmtFlags(configFile string, overwrite, diff, imports bool) Flags {
	fs := pflag.NewFlagSet("fmt", pflag.ContinueOnError)
	fs.StringP("config", "c", "", "")
	fs.BoolP("overwrite", "w", false, "")
	fs.BoolP("diff", "d", false, "")
	fs.Bool("imports", false, "")
	if configFile != "" {
		_ = fs.Parse([]string{configFile})
	}
	if overwrite {
		_ = fs.Set("overwrite", "true")
	}
	if diff {
		_ = fs.Set("diff", "true")
	}
	if imports {
		_ = fs.Set("imports", "true")
	}
	return Flags{fs}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCmdFmtImportsStdinRejected verifies that --imports with stdin is rejected.
func TestCmdFmtImportsStdinRejected(t *testing.T) {
	fl := newFmtFlags("-", false, false, true)
	code, err := cmdFmt(fl)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "cannot use --imports") {
		t.Errorf("unexpected error message: %v", err)
	}
	if code != caddy.ExitCodeFailedStartup {
		t.Errorf("expected ExitCodeFailedStartup, got %d", code)
	}
}

// TestCmdFmtImportsOverwrite verifies that --imports --overwrite rewrites both
// the root Caddyfile and its imported file.
func TestCmdFmtImportsOverwrite(t *testing.T) {
	dir := t.TempDir()

	rootPath := filepath.Join(dir, "Caddyfile")
	sitesDir := filepath.Join(dir, "sites")
	if err := os.MkdirAll(sitesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	importedPath := filepath.Join(sitesDir, "a.caddy")

	// Root imports the sites file; both are deliberately messy.
	writeTestFile(t, rootPath, "import sites/a.caddy\n")
	writeTestFile(t, importedPath, "localhost{\nrespond   200\n}\n")

	fl := newFmtFlags(rootPath, true, false, true)
	code, err := cmdFmt(fl)
	if err != nil {
		t.Fatalf("cmdFmt returned error: %v", err)
	}
	if code != caddy.ExitCodeSuccess {
		t.Errorf("expected ExitCodeSuccess, got %d", code)
	}

	// The imported file should now be properly formatted.
	got, err := os.ReadFile(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "localhost {\n\trespond 200\n}\n"
	if string(got) != want {
		t.Errorf("imported file content = %q, want %q", string(got), want)
	}
}

// TestCmdFmtImportsPrintsHeaders verifies that without --overwrite each file's
// output is preceded by a "# <path>" header line.
func TestCmdFmtImportsPrintsHeaders(t *testing.T) {
	dir := t.TempDir()

	rootPath := filepath.Join(dir, "Caddyfile")
	sitesDir := filepath.Join(dir, "sites")
	if err := os.MkdirAll(sitesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	importedPath := filepath.Join(sitesDir, "b.caddy")

	writeTestFile(t, rootPath, "import sites/b.caddy\n")
	writeTestFile(t, importedPath, "localhost {\n\trespond 200\n}\n")

	// Capture stdout by redirecting os.Stdout.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	fl := newFmtFlags(rootPath, false, false, true)
	code, fmtErr := cmdFmt(fl)

	w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if fmtErr != nil {
		t.Fatalf("cmdFmt returned error: %v", fmtErr)
	}
	if code != caddy.ExitCodeSuccess {
		t.Errorf("expected ExitCodeSuccess, got %d", code)
	}
	if !strings.Contains(output, "# "+rootPath) {
		t.Errorf("output missing root header; got:\n%s", output)
	}
	if !strings.Contains(output, "# "+importedPath) {
		t.Errorf("output missing imported file header; got:\n%s", output)
	}
}

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
