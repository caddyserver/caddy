package filesystems

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
)

type openCountingFS struct {
	fstest.MapFS
	opens int
}

func (o *openCountingFS) Open(name string) (fs.File, error) {
	o.opens++
	return o.MapFS.Open(name)
}

func TestWrapperFsStat(t *testing.T) {
	for i, tc := range []struct {
		hideStatFS bool
		wantOpens  int
	}{
		{hideStatFS: false, wantOpens: 0},
		{hideStatFS: true, wantOpens: 1},
	} {
		inner := &openCountingFS{MapFS: fstest.MapFS{"file": {Data: []byte("data")}}}
		var fsys fs.FS = inner
		if tc.hideStatFS {
			fsys = struct{ fs.FS }{inner}
		}
		var m FileSystemMap
		m.Register("test", fsys)
		wrapped, _ := m.Get("test")

		info, err := fs.Stat(wrapped, "file")
		if err != nil {
			t.Fatalf("Test %d: unexpected error: %v", i, err)
		}
		if info.Size() != 4 {
			t.Errorf("Test %d: expected size 4, got %d", i, info.Size())
		}
		if inner.opens != tc.wantOpens {
			t.Errorf("Test %d: expected %d opens, got %d", i, tc.wantOpens, inner.opens)
		}
	}
}

func TestDefaultFileSystemStatDoesNotOpen(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file that cannot be opened")
	}
	name := filepath.Join(t.TempDir(), "unreadable")
	if err := os.WriteFile(name, []byte("data"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := DefaultFileSystem.Open(name); err == nil {
		t.Fatal("expected open to fail")
	}

	info, err := fs.Stat(DefaultFileSystem, name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Size() != 4 {
		t.Errorf("expected size 4, got %d", info.Size())
	}
}
