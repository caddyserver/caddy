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

package fileserver

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// failingDirEntry is a fs.DirEntry whose Info() always fails, simulating an
// entry that vanished between ReadDir and stat (e.g. deleted concurrently).
// It's used to verify that directoryListing skips such entries without
// affecting the rest of the listing, the same way it does today.
type failingDirEntry struct{ name string }

func (f failingDirEntry) Name() string               { return f.name }
func (f failingDirEntry) IsDir() bool                { return false }
func (f failingDirEntry) Type() fs.FileMode          { return 0 }
func (f failingDirEntry) Info() (fs.FileInfo, error) { return nil, fs.ErrNotExist }

// TestDirectoryListing verifies directoryListing's aggregate output
// (NumDirs, NumFiles, the two total-size counters, and the resulting items)
// against a directory with regular files, a subdirectory, and symlinks to
// each - and confirms the result is identical whether entries are stat'd
// with the default (parallel) concurrency or forced down to Concurrency: 1
// (effectively sequential), to guard against the chunk-splitting rewrite
// introducing an aggregation bug.
func TestDirectoryListing(t *testing.T) {
	dir := t.TempDir()
	makeBenchDir(t, dir, 3) // file-0.txt, file-1.txt, file-2.txt (1 byte each), subdir/, symlink-to-file, symlink-to-dir

	fileSystem, entries := readBenchDirEntries(t, dir)
	entries = append(entries, failingDirEntry{name: "gone.txt"})

	linkInfo, err := os.Lstat(filepath.Join(dir, "symlink-to-file"))
	if err != nil {
		t.Fatal(err)
	}
	wantNumFiles := 4 // 3 regular files + symlink-to-file
	wantNumDirs := 2  // subdir + symlink-to-dir
	wantTotalFileSize := int64(3) + linkInfo.Size()
	wantTotalFileSizeFollowingSymlinks := int64(3) + 1 // symlink-to-file's target (file-0.txt) is 1 byte
	wantNames := map[string]bool{
		"file-0.txt":      false,
		"file-1.txt":      false,
		"file-2.txt":      false,
		"subdir/":         false,
		"symlink-to-file": false,
		"symlink-to-dir/": false,
	}

	ctx := context.Background()
	repl := caddy.NewReplacer()

	check := func(t *testing.T, l *browseTemplateContext) {
		t.Helper()

		if l.NumFiles != wantNumFiles {
			t.Errorf("NumFiles = %d, want %d", l.NumFiles, wantNumFiles)
		}
		if l.NumDirs != wantNumDirs {
			t.Errorf("NumDirs = %d, want %d", l.NumDirs, wantNumDirs)
		}
		if l.TotalFileSize != wantTotalFileSize {
			t.Errorf("TotalFileSize = %d, want %d", l.TotalFileSize, wantTotalFileSize)
		}
		if l.TotalFileSizeFollowingSymlinks != wantTotalFileSizeFollowingSymlinks {
			t.Errorf("TotalFileSizeFollowingSymlinks = %d, want %d", l.TotalFileSizeFollowingSymlinks, wantTotalFileSizeFollowingSymlinks)
		}
		if len(l.Items) != wantNumFiles+wantNumDirs {
			t.Fatalf("len(Items) = %d, want %d", len(l.Items), wantNumFiles+wantNumDirs)
		}

		gotNames := make(map[string]bool, len(wantNames))
		for k := range wantNames {
			gotNames[k] = false
		}
		for _, item := range l.Items {
			if _, ok := gotNames[item.Name]; !ok {
				t.Errorf("unexpected item in listing: %q", item.Name)
				continue
			}
			gotNames[item.Name] = true
			if item.Tpl != l {
				t.Errorf("item %q: Tpl does not point back to the listing", item.Name)
			}
		}
		for name, seen := range gotNames {
			if !seen {
				t.Errorf("expected item %q missing from listing", name)
			}
		}
	}

	fsrv := benchFileServer()
	t.Run("default concurrency", func(t *testing.T) {
		l := fsrv.directoryListing(ctx, fileSystem, time.Time{}, entries, true, dir, "/", repl)
		check(t, l)
	})

	fsrv.Browse.Concurrency = 1
	t.Run("concurrency=1", func(t *testing.T) {
		l := fsrv.directoryListing(ctx, fileSystem, time.Time{}, entries, true, dir, "/", repl)
		check(t, l)
	})

	fsrv.Browse.Concurrency = 0
	t.Run("concurrency=0 (treated as default)", func(t *testing.T) {
		l := fsrv.directoryListing(ctx, fileSystem, time.Time{}, entries, true, dir, "/", repl)
		check(t, l)
	})

	t.Run("cancelled context does not panic", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()
		l := fsrv.directoryListing(cancelCtx, fileSystem, time.Time{}, entries, true, dir, "/", repl)
		if l == nil {
			t.Fatal("expected non-nil listing even with cancelled context")
		}
	})
}

func TestBreadcrumbs(t *testing.T) {
	testdata := []struct {
		path     string
		expected []crumb
	}{
		{"", []crumb{}},
		{"/", []crumb{{Text: "/"}}},
		{"/foo/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "foo"},
		}},
		{"/foo/bar/", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "foo"},
			{Link: "", Text: "bar"},
		}},
		{"/foo bar/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "foo bar"},
		}},
		{"/foo bar/baz/", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "foo bar"},
			{Link: "", Text: "baz"},
		}},
		{"/100%25 test coverage/is a lie/", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "100% test coverage"},
			{Link: "", Text: "is a lie"},
		}},
		{"/AC%2FDC/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "AC/DC"},
		}},
		{"/foo/%2e%2e%2f/bar", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: "../"},
			{Link: "", Text: "bar"},
		}},
		{"/foo/../bar", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: ".."},
			{Link: "", Text: "bar"},
		}},
		{"foo/bar/baz", []crumb{
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: "bar"},
			{Link: "", Text: "baz"},
		}},
		{"/qux/quux/corge/", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "qux"},
			{Link: "../", Text: "quux"},
			{Link: "", Text: "corge"},
		}},
		{"/مجلد/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "مجلد"},
		}},
		{"/مجلد-1/مجلد-2", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "مجلد-1"},
			{Link: "", Text: "مجلد-2"},
		}},
		{"/مجلد%2F1", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "مجلد/1"},
		}},
	}

	for testNum, d := range testdata {
		l := browseTemplateContext{Path: d.path}
		actual := l.Breadcrumbs()
		if len(actual) != len(d.expected) {
			t.Errorf("Test %d: Got %d components but expected %d; got: %+v", testNum, len(actual), len(d.expected), actual)
			continue
		}
		for i, c := range actual {
			if c != d.expected[i] {
				t.Errorf("Test %d crumb %d: got %#v but expected %#v at index %d", testNum, i, c, d.expected[i], i)
			}
		}
	}
}
