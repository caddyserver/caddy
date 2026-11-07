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
	"net/http/httptest"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestNatLexSort confirms that both sort methods work: For "lex", a
// lexicographic sort returns "foo1.txt" < "foo10.txt" < "foo2.txt", while a
// "natural" sort returns a human-intuitive order: "foo2.txt" < "foo10.txt"
func TestNatLexSort(t *testing.T) {
	fsrv := &FileServer{Browse: &Browse{}}

	base := "./testdata"
	dirName := "natsort"

	fsys := os.DirFS(base)
	f, err := fsys.Open(dirName)
	if err != nil {
		t.Fatalf("opening testdata dir: %v", err)
	}
	defer f.Close()

	repl := caddyhttp.NewTestReplacer(httptest.NewRequest("GET", "/", nil))

	listing, err := fsrv.loadDirectoryContents(context.Background(), fsys, f.(fs.ReadDirFile), base, "/natsort/", repl)
	if err != nil {
		t.Fatalf("loadDirectoryContents returned error: %v", err)
	}

	if len(listing.Items) != 3 {
		t.Fatalf("expected 3 items in listing, got %d", len(listing.Items))
	}

	cases := []struct {
		Method string
		Want   []string
	}{
		{sortMethodNatural, []string{"foo1.txt", "foo2.txt", "foo10.txt"}},
		{sortMethodLexicographic, []string{"foo1.txt", "foo10.txt", "foo2.txt"}},
	}

	for _, c := range cases {
		listing.applySortAndLimit(sortByNameDirFirst, sortOrderAsc, c.Method, "", "")

		got := []string{}
		for _, item := range listing.Items {
			got = append(got, item.Name)
		}

		if len(got) != len(c.Want) {
			t.Fatalf("expected %v items, got %v", len(got), len(c.Want))
		}

		for i := range c.Want {
			if got[i] != c.Want[i] {
				t.Fatalf("unexpected item at index %v: got %v, want %v", i, got, c.Want)
			}
		}
	}
}
