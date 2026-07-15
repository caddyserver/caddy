package caddycmd

import (
	"bytes"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func captureStdout(t *testing.T, fn func() (int, error)) (string, int, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	code, callErr := fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = oldStdout
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return string(output), code, callErr
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
	writeTestFile(t, rootPath, "import    sites/a.caddy\n")
	writeTestFile(t, importedPath, "localhost {\nrespond   200\n}\n")
	if err := os.Chmod(rootPath, 0o640); err != nil {
		t.Fatal(err)
	}
	rootInfoBefore, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	importedInfoBefore, err := os.Stat(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	// Windows loads FileInfo IDs lazily when SameFile is first called. Prime
	// them before replacement so these values continue to identify the old files.
	if !os.SameFile(rootInfoBefore, rootInfoBefore) || !os.SameFile(importedInfoBefore, importedInfoBefore) {
		t.Fatal("could not snapshot file identity")
	}

	fl := newFmtFlags(rootPath, true, false, true)
	code, err := cmdFmt(fl)
	if err != nil {
		t.Fatalf("cmdFmt returned error: %v", err)
	}
	if code != caddy.ExitCodeSuccess {
		t.Errorf("expected ExitCodeSuccess, got %d", code)
	}

	gotRoot, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := "import sites/a.caddy\n"; string(gotRoot) != want {
		t.Errorf("root file content = %q, want %q", string(gotRoot), want)
	}
	gotRootInfo, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotRootInfo.Mode().Perm() != rootInfoBefore.Mode().Perm() {
		t.Errorf("root file permissions = %o, want %o", gotRootInfo.Mode().Perm(), rootInfoBefore.Mode().Perm())
	}
	if os.SameFile(rootInfoBefore, gotRootInfo) {
		t.Error("root file was rewritten in place instead of atomically replaced")
	}

	got, err := os.ReadFile(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "localhost {\n\trespond 200\n}\n"
	if string(got) != want {
		t.Errorf("imported file content = %q, want %q", string(got), want)
	}
	gotImportedInfo, err := os.Stat(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(importedInfoBefore, gotImportedInfo) {
		t.Error("imported file was rewritten in place instead of atomically replaced")
	}
}

func TestCmdFmtImportsPreviewReportsFormattingDifference(t *testing.T) {
	for _, diff := range []bool{false, true} {
		t.Run(map[bool]string{false: "preview", true: "diff"}[diff], func(t *testing.T) {
			dir := t.TempDir()
			rootPath := filepath.Join(dir, "Caddyfile")
			importedPath := filepath.Join(dir, "imported.caddy")
			writeTestFile(t, rootPath, "import imported.caddy\n")
			writeTestFile(t, importedPath, "localhost {\nrespond  200\n}\n")

			output, code, err := captureStdout(t, func() (int, error) {
				return cmdFmt(newFmtFlags(rootPath, false, diff, true))
			})
			if err == nil || !strings.Contains(err.Error(), "input is not formatted") {
				t.Fatalf("expected formatting error, got %v", err)
			}
			if code != caddy.ExitCodeFailedStartup {
				t.Errorf("expected ExitCodeFailedStartup, got %d", code)
			}
			if !strings.Contains(output, "# "+canonicalTestPath(t, importedPath)) {
				t.Errorf("output missing imported file header; got:\n%s", output)
			}
			if diff && !strings.Contains(output, "+ \trespond 200") {
				t.Errorf("output missing formatted diff; got:\n%s", output)
			}
			if !diff && !strings.Contains(output, "localhost {\n\trespond 200\n}") {
				t.Errorf("output missing formatted preview; got:\n%s", output)
			}
		})
	}
}

func TestOverwriteFormattedFilesRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target")
	linkPath := filepath.Join(dir, "link")
	writeTestFile(t, targetPath, "original")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := overwriteFormattedFiles([]caddyfile.FormattedFile{{Path: linkPath, Content: []byte("changed")}})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("original")) {
		t.Errorf("symlink target changed to %q", got)
	}
}

func TestOverwriteFormattedFilesReportsPartialUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	writeTestFile(t, path, "localhost {\nrespond  200\n}\n")
	formatted := []byte("localhost {\n\trespond 200\n}\n")

	err := overwriteFormattedFiles([]caddyfile.FormattedFile{
		{Path: path, Content: formatted},
		{Path: path, Content: formatted},
	})
	if err == nil || !strings.Contains(err.Error(), "after replacing 1 of 2 files") ||
		!strings.Contains(err.Error(), "may be partially updated") {
		t.Fatalf("expected partial-update error, got %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, formatted) {
		t.Errorf("first replacement content = %q, want %q", got, formatted)
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

	fl := newFmtFlags(rootPath, false, false, true)
	output, code, fmtErr := captureStdout(t, func() (int, error) { return cmdFmt(fl) })

	if fmtErr != nil {
		t.Fatalf("cmdFmt returned error: %v", fmtErr)
	}
	if code != caddy.ExitCodeSuccess {
		t.Errorf("expected ExitCodeSuccess, got %d", code)
	}
	if !strings.Contains(output, "# "+canonicalTestPath(t, rootPath)) {
		t.Errorf("output missing root header; got:\n%s", output)
	}
	if !strings.Contains(output, "# "+canonicalTestPath(t, importedPath)) {
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
