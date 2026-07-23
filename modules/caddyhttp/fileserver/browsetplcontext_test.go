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

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

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

// TestDirectoryListingParity checks that directoryListing (the optimized
// implementation) and directoryListingOld (the original, kept around only
// for this comparison and for benchmarking) produce equivalent listings for
// the same directory, including regular files, a hidden file, a symlink to
// a file, a symlink to a directory, and a broken symlink.
func TestDirectoryListingParity(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"a.txt", "b.txt", "hidden.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "a.txt"), filepath.Join(dir, "symlink-to-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(subdir, filepath.Join(dir, "symlink-to-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "symlink-broken")); err != nil {
		t.Fatal(err)
	}

	fileSystem := os.DirFS(dir)
	entries, err := fileSystem.(fs.ReadDirFS).ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	fsrv := &FileServer{
		Hide:   []string{"hidden.txt"},
		Browse: &Browse{RevealSymlinks: true},
		logger: zap.NewNop(),
	}

	oldCtx := fsrv.directoryListingOld(context.Background(), fileSystem, time.Time{}, entries, true, dir, "/", caddy.NewReplacer())
	newCtx := fsrv.directoryListing(context.Background(), fileSystem, time.Time{}, entries, true, dir, "/", caddy.NewReplacer())

	if oldCtx.NumDirs != newCtx.NumDirs {
		t.Errorf("NumDirs: old=%d new=%d", oldCtx.NumDirs, newCtx.NumDirs)
	}
	if oldCtx.NumFiles != newCtx.NumFiles {
		t.Errorf("NumFiles: old=%d new=%d", oldCtx.NumFiles, newCtx.NumFiles)
	}
	if oldCtx.TotalFileSize != newCtx.TotalFileSize {
		t.Errorf("TotalFileSize: old=%d new=%d", oldCtx.TotalFileSize, newCtx.TotalFileSize)
	}
	if oldCtx.TotalFileSizeFollowingSymlinks != newCtx.TotalFileSizeFollowingSymlinks {
		t.Errorf("TotalFileSizeFollowingSymlinks: old=%d new=%d", oldCtx.TotalFileSizeFollowingSymlinks, newCtx.TotalFileSizeFollowingSymlinks)
	}
	if !oldCtx.lastModified.Equal(newCtx.lastModified) {
		t.Errorf("lastModified: old=%v new=%v", oldCtx.lastModified, newCtx.lastModified)
	}
	if len(oldCtx.Items) != len(newCtx.Items) {
		t.Fatalf("Items length: old=%d new=%d", len(oldCtx.Items), len(newCtx.Items))
	}

	for i := range oldCtx.Items {
		o, n := oldCtx.Items[i], newCtx.Items[i]
		if o.Name != n.Name || o.Size != n.Size || o.URL != n.URL ||
			!o.ModTime.Equal(n.ModTime) || o.Mode != n.Mode ||
			o.IsDir != n.IsDir || o.IsSymlink != n.IsSymlink || o.SymlinkPath != n.SymlinkPath {
			t.Errorf("item %d mismatch:\n old=%#v\n new=%#v", i, o, n)
		}
	}
}

// TestApplySortAndLimitParity checks that applySortAndLimit (which caches
// each item's lowercase name once up front) and applySortAndLimitOld (which
// recomputes it on every comparison, kept only for benchmarking) produce the
// same resulting order for every sort mode and order.
func TestApplySortAndLimitParity(t *testing.T) {
	names := []string{"Banana", "apple", "Cherry", "date", "Elderberry", "fig", "Grape"}
	sizes := []int64{30, 10, 50, 5, 70, 1, 20}
	dirs := []bool{false, true, false, true, false, false, true}

	makeItems := func() []fileInfo {
		items := make([]fileInfo, len(names))
		base := time.Now()
		for i, name := range names {
			items[i] = fileInfo{
				Name:    name,
				Size:    sizes[i],
				IsDir:   dirs[i],
				ModTime: base.Add(time.Duration(i) * time.Minute),
			}
		}
		return items
	}

	for _, sortParam := range []string{sortByName, sortByNameDirFirst, sortBySize, sortByTime} {
		for _, orderParam := range []string{sortOrderAsc, sortOrderDesc} {
			t.Run(sortParam+"_"+orderParam, func(t *testing.T) {
				oldCtx := &browseTemplateContext{Items: makeItems()}
				newCtx := &browseTemplateContext{Items: makeItems()}

				oldCtx.applySortAndLimitOld(sortParam, orderParam, "", "")
				newCtx.applySortAndLimit(sortParam, orderParam, "", "")

				if len(oldCtx.Items) != len(newCtx.Items) {
					t.Fatalf("Items length: old=%d new=%d", len(oldCtx.Items), len(newCtx.Items))
				}
				for i := range oldCtx.Items {
					if oldCtx.Items[i].Name != newCtx.Items[i].Name {
						t.Errorf("position %d: old=%q new=%q", i, oldCtx.Items[i].Name, newCtx.Items[i].Name)
					}
				}
			})
		}
	}
}
