package filesystems

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestFileSystemMapDefaultKey(t *testing.T) {
	m := &FileSystemMap{}

	// Empty key should map to default
	if m.key("") != DefaultFileSystemKey {
		t.Errorf("empty key should map to %q, got %q", DefaultFileSystemKey, m.key(""))
	}

	// Non-empty key should be returned as-is
	if m.key("custom") != "custom" {
		t.Errorf("non-empty key should be returned as-is, got %q", m.key("custom"))
	}
}

func TestFileSystemMapRegisterAndGet(t *testing.T) {
	m := &FileSystemMap{}
	testFS := fstest.MapFS{
		"hello.txt": &fstest.MapFile{Data: []byte("hello")},
	}

	m.Register("test", testFS)

	got, ok := m.Get("test")
	if !ok {
		t.Fatal("expected to find registered filesystem")
	}
	if got == nil {
		t.Fatal("expected non-nil filesystem")
	}

	// Verify the filesystem works
	f, err := got.Open("hello.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	f.Close()
}

func TestFileSystemMapGetNonExistent(t *testing.T) {
	m := &FileSystemMap{}

	_, ok := m.Get("nonexistent")
	if ok {
		t.Error("expected Get to return false for nonexistent key")
	}
}

func TestFileSystemMapDefault(t *testing.T) {
	m := &FileSystemMap{}

	d := m.Default()
	if d == nil {
		t.Fatal("Default() should never return nil")
	}
}

func TestFileSystemMapGetDefaultLazyInit(t *testing.T) {
	m := &FileSystemMap{}

	// Getting the default key before any registration should
	// auto-initialize to DefaultFileSystem
	got, ok := m.Get(DefaultFileSystemKey)
	if !ok {
		t.Fatal("expected default filesystem to be auto-initialized")
	}
	if got == nil {
		t.Fatal("expected non-nil default filesystem")
	}
}

func TestFileSystemMapUnregister(t *testing.T) {
	m := &FileSystemMap{}
	testFS := fstest.MapFS{}

	m.Register("test", testFS)
	m.Unregister("test")

	_, ok := m.Get("test")
	if ok {
		t.Error("expected filesystem to be unregistered")
	}
}

func TestFileSystemMapUnregisterDefault(t *testing.T) {
	m := &FileSystemMap{}
	customFS := fstest.MapFS{}

	// Override default
	m.Register("", customFS)
	// Unregister default should reset to OsFS, not delete
	m.Unregister("")

	d := m.Default()
	if d == nil {
		t.Fatal("unregistering default should reset it, not delete it")
	}
}

func TestFileSystemMapRegisterNil(t *testing.T) {
	m := &FileSystemMap{}
	testFS := fstest.MapFS{}

	// Register then register nil (should unregister)
	m.Register("test", testFS)
	m.Register("test", nil)

	_, ok := m.Get("test")
	if ok {
		t.Error("registering nil should unregister the filesystem")
	}
}

func TestFileSystemMapEmptyKeyIsDefault(t *testing.T) {
	m := &FileSystemMap{}
	testFS := fstest.MapFS{
		"test.txt": &fstest.MapFile{Data: []byte("test")},
	}

	// Register with empty key should register as default
	m.Register("", testFS)

	got, ok := m.Get("")
	if !ok {
		t.Fatal("expected to find filesystem registered with empty key")
	}

	// Should also be accessible via default key
	got2, ok := m.Get(DefaultFileSystemKey)
	if !ok {
		t.Fatal("expected to find filesystem via default key")
	}

	// Both should work
	if got == nil || got2 == nil {
		t.Fatal("expected non-nil filesystems")
	}
}

func TestFileSystemMapGetTrimsWhitespace(t *testing.T) {
	m := &FileSystemMap{}
	testFS := fstest.MapFS{}

	m.Register("test", testFS)

	// Get with whitespace-padded key should match
	got, ok := m.Get("test ")
	if !ok {
		t.Fatal("expected Get to trim whitespace from key")
	}
	if got == nil {
		t.Fatal("expected non-nil filesystem")
	}
}

func TestOsFSInterfaces(t *testing.T) {
	var osFS OsFS

	// Verify interface compliance at compile time (already done with var _ checks)
	// but test that the methods exist and are callable
	var _ fs.FS = osFS
	var _ fs.StatFS = osFS
	var _ fs.GlobFS = osFS
	var _ fs.ReadDirFS = osFS
	var _ fs.ReadFileFS = osFS
}
