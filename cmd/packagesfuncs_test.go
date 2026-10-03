package caddycmd

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

type trackingReadCloser struct {
	*bytes.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestDownloadBuildClosesErrorResponseBody(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	body := &trackingReadCloser{Reader: bytes.NewReader([]byte(`{"error":{"message":"bad request","id":"test"}}`))}
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       body,
			Request:    req,
		}, nil
	})

	if _, err := downloadBuild(url.Values{}); err == nil {
		t.Fatal("downloadBuild succeeded, want error")
	}
	if !body.closed {
		t.Fatal("downloadBuild did not close the error response body")
	}
}

func TestModuleContainsPackage(t *testing.T) {
	tests := []struct {
		name        string
		modulePath  string
		packagePath string
		want        bool
	}{
		{name: "module root", modulePath: "example.com/mod", packagePath: "example.com/mod", want: true},
		{name: "module package", modulePath: "example.com/mod", packagePath: "example.com/mod/pkg", want: true},
		{name: "shared prefix", modulePath: "example.com/mod", packagePath: "example.com/module", want: false},
		{name: "caddy module shared prefix", modulePath: "github.com/caddyserver/caddy/v2", packagePath: "github.com/caddyserver/caddy/v20", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := moduleContainsPackage(tt.modulePath, tt.packagePath); got != tt.want {
				t.Fatalf("moduleContainsPackage(%q, %q) = %v, want %v", tt.modulePath, tt.packagePath, got, tt.want)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

var _ io.ReadCloser = (*trackingReadCloser)(nil)

func TestResolveExecutable(t *testing.T) {
	dir := t.TempDir()

	writeBinary := func(name string, perm os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("caddy"), perm); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("regular file is replaced in place", func(t *testing.T) {
		path := writeBinary("caddy", 0o755)

		gotPath, gotStat, err := resolveExecutable(path)
		if err != nil {
			t.Fatalf("resolveExecutable: %v", err)
		}
		if gotPath != path {
			t.Errorf("path = %q, want %q", gotPath, path)
		}
		if gotStat.Mode().Perm() != 0o755 {
			t.Errorf("mode = %v, want %v", gotStat.Mode().Perm(), os.FileMode(0o755))
		}
	})

	// A package manager (Homebrew) links its bin dir into a versioned directory
	// and owns the link, so the binary behind the link must be the one replaced.
	t.Run("symlink resolves to its target", func(t *testing.T) {
		target := writeBinary(filepath.Join("Cellar", "caddy", "2.11.7", "bin", "caddy"), 0o755)
		link := filepath.Join(dir, "bin", "caddy")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		// EvalSymlinks on the expectation too: the temp dir itself may contain
		// symlinked components (on macOS, /var -> /private/var).
		wantPath, err := filepath.EvalSymlinks(target)
		if err != nil {
			t.Fatal(err)
		}
		wantStat, err := os.Stat(wantPath)
		if err != nil {
			t.Fatal(err)
		}

		gotPath, gotStat, err := resolveExecutable(link)
		if err != nil {
			t.Fatalf("resolveExecutable: %v", err)
		}
		if gotPath != wantPath {
			t.Errorf("path = %q, want %q (the target, not the link)", gotPath, wantPath)
		}
		// The link's own mode is ModeSymlink|0777; the replacement file must be
		// created with the target's permissions instead.
		if gotStat.Mode() != wantStat.Mode() {
			t.Errorf("mode = %v, want the target's %v", gotStat.Mode(), wantStat.Mode())
		}
	})
}
