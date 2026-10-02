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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/filesystems"
)

func TestDirectoryListingSymlinks(t *testing.T) {
	for _, dirPath := range []string{
		"/",
		"/nested/",
		"/Amelia Watson/",
		"/音乐/",
		"/100% coverage/",
		"/literal%20name/",
		"/literal%2Fname/",
		"/parent/Amelia Watson/",
	} {
		t.Run(dirPath, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(dirPath, "/")))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			targetRoot := t.TempDir()
			dirTarget := filepath.Join(targetRoot, "directory")
			if err := os.Mkdir(dirTarget, 0o755); err != nil {
				t.Fatal(err)
			}
			fileTarget := filepath.Join(targetRoot, "file.txt")
			fileContents := []byte("symlink target contents")
			if err := os.WriteFile(fileTarget, fileContents, 0o600); err != nil {
				t.Fatal(err)
			}

			links := map[string]string{
				"directory link": dirTarget,
				"file link":      fileTarget,
				"broken link":    filepath.Join(targetRoot, "missing"),
			}
			for name, target := range links {
				if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
					t.Skipf("symlink not supported on this platform: %v", err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}

			fsrv := FileServer{
				Browse: &Browse{RevealSymlinks: true},
				logger: zap.NewNop(),
			}
			u := url.URL{Path: dirPath}
			escapedPath := u.EscapedPath()
			listing := fsrv.directoryListing(context.Background(), filesystems.OsFS{}, time.Time{}, entries, dirPath != "/", root, escapedPath, caddy.NewReplacer())
			if listing.Path != escapedPath {
				t.Errorf("listing path: got %q, want %q", listing.Path, escapedPath)
			}
			if listing.NumDirs != 1 || listing.NumFiles != 2 || len(listing.Items) != len(links) {
				t.Errorf("listing: got %d directories, %d files, %d items; want 1 directory, 2 files, 3 items", listing.NumDirs, listing.NumFiles, len(listing.Items))
			}
			for _, item := range listing.Items {
				name := strings.TrimSuffix(item.Name, "/")
				if !item.IsSymlink {
					t.Errorf("%q should be a symlink", item.Name)
				}
				if item.SymlinkPath != links[name] {
					t.Errorf("%q symlink target: got %q, want %q", item.Name, item.SymlinkPath, links[name])
				}
				switch name {
				case "directory link":
					if !item.IsDir || item.Name != "directory link/" || item.URL != "./directory%20link/" {
						t.Errorf("directory symlink: got IsDir=%v, Name=%q, URL=%q", item.IsDir, item.Name, item.URL)
					}
				case "file link":
					if item.IsDir || item.Size != int64(len(fileContents)) {
						t.Errorf("file symlink: got IsDir=%v, Size=%d; want false, %d", item.IsDir, item.Size, len(fileContents))
					}
				case "broken link":
					if item.IsDir {
						t.Error("broken symlink should not be a directory")
					}
				default:
					t.Errorf("unexpected listing entry %q", item.Name)
				}
			}
		})
	}
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
