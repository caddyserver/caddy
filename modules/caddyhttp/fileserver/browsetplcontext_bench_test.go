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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// makeBenchDir populates dir with n regular files and a handful of
// symlinks (both to files and to a subdirectory), mirroring what a
// real, large, browsable directory tends to contain.
func makeBenchDir(tb testing.TB, dir string, n int) {
	tb.Helper()

	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		tb.Fatal(err)
	}

	for i := range n {
		name := filepath.Join(dir, fmt.Sprintf("file-%d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			tb.Fatal(err)
		}
	}

	target := filepath.Join(dir, "file-0.txt")
	if err := os.Symlink(target, filepath.Join(dir, "symlink-to-file")); err != nil {
		tb.Fatal(err)
	}
	if err := os.Symlink(subdir, filepath.Join(dir, "symlink-to-dir")); err != nil {
		tb.Fatal(err)
	}
}

// readBenchDirEntries reads all entries of dir once, up front, so that
// benchmark iterations measure only the cost of directoryListing itself
// (allocations, stat calls per entry) rather than the readdir syscall.
//
// It deliberately opens the directory and calls the ReadDir method on the
// resulting file (like loadDirectoryContents does in production), not
// fs.ReadDir/os.ReadDir - the latter sort entries by filename before
// returning them, which would silently hand the sort benchmarks
// already-sorted input and let sort.Sort's adaptive algorithm breeze
// through with far fewer comparisons than a real, filesystem-ordered
// directory listing requires.
func readBenchDirEntries(tb testing.TB, dir string) (fs.FS, []fs.DirEntry) {
	tb.Helper()

	fileSystem := os.DirFS(dir)
	f, err := fileSystem.Open(".")
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()

	entries, err := f.(fs.ReadDirFile).ReadDir(-1)
	if err != nil {
		tb.Fatal(err)
	}
	return fileSystem, entries
}

func benchFileServer() *FileServer {
	return &FileServer{
		Browse: &Browse{},
		logger: zap.NewNop(),
	}
}

func benchmarkDirectoryListing(b *testing.B, n int, listFn func(fsrv *FileServer, ctx context.Context, fileSystem fs.FS, entries []fs.DirEntry, root string) *browseTemplateContext) {
	dir := b.TempDir()
	makeBenchDir(b, dir, n)
	fileSystem, entries := readBenchDirEntries(b, dir)
	fsrv := benchFileServer()
	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		listFn(fsrv, ctx, fileSystem, entries, dir)
	}
}

func BenchmarkDirectoryListingOld(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkDirectoryListing(b, n, func(fsrv *FileServer, ctx context.Context, fileSystem fs.FS, entries []fs.DirEntry, root string) *browseTemplateContext {
				return fsrv.directoryListingOld(ctx, fileSystem, time.Time{}, entries, true, root, "/", caddy.NewReplacer())
			})
		})
	}
}

func BenchmarkDirectoryListingNew(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkDirectoryListing(b, n, func(fsrv *FileServer, ctx context.Context, fileSystem fs.FS, entries []fs.DirEntry, root string) *browseTemplateContext {
				return fsrv.directoryListing(ctx, fileSystem, time.Time{}, entries, true, root, "/", caddy.NewReplacer())
			})
		})
	}
}

// ---------------------------------------------------------------------
// Sort comparator benchmarks (byName/byNameDirFirst/bySize vs. their *Old
// counterparts). These isolate the cost of the comparator itself: the
// nameLower cache (when the comparator being measured needs it) is filled
// outside the timed portion, since in production it's filled once by
// applySortAndLimit rather than repeatedly inside Less. The combined,
// real-world cost of filling the cache and sorting is what
// BenchmarkDirectoryListingAndSort further down measures.
// ---------------------------------------------------------------------

// makeBenchItems builds n synthetic fileInfo items (no disk I/O), mixing
// upper/lower case names and marking roughly 1 in 10 as directories, to
// exercise the sort comparators - including bySize's directory name
// tie-break - the way a real, large, mixed listing would.
func makeBenchItems(n int) []fileInfo {
	items := make([]fileInfo, n)
	for i := range n {
		name := fmt.Sprintf("file_%d.txt", i)
		if i%2 == 0 {
			name = fmt.Sprintf("FILE_%d.TXT", i)
		}
		items[i] = fileInfo{
			Name:  name,
			Size:  int64(i),
			IsDir: i%10 == 0,
		}
	}
	return items
}

func fillNameLower(items []fileInfo) {
	for i := range items {
		items[i].nameLower = strings.ToLower(items[i].Name)
	}
}

// benchmarkSort times sortFn against a fresh, unsorted copy of a synthetic
// item set on every iteration. The copy, and the optional prepare step
// (e.g. filling the nameLower cache), happen outside the timed portion so
// the benchmark isolates the cost of the sort itself.
func benchmarkSort(b *testing.B, n int, prepare func(items []fileInfo), sortFn func(items []fileInfo)) {
	pristine := makeBenchItems(n)
	items := make([]fileInfo, n)

	for b.Loop() {
		b.StopTimer()
		copy(items, pristine)
		if prepare != nil {
			prepare(items)
		}
		b.StartTimer()
		sortFn(items)
	}
}

func BenchmarkSortByNameOld(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkSort(b, n, nil, func(items []fileInfo) {
				sort.Sort(byNameOld(browseTemplateContext{Items: items}))
			})
		})
	}
}

func BenchmarkSortByNameNew(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkSort(b, n, fillNameLower, func(items []fileInfo) {
				sort.Sort(byName(browseTemplateContext{Items: items}))
			})
		})
	}
}

func BenchmarkSortByNameDirFirstOld(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkSort(b, n, nil, func(items []fileInfo) {
				sort.Sort(byNameDirFirstOld(browseTemplateContext{Items: items}))
			})
		})
	}
}

func BenchmarkSortByNameDirFirstNew(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkSort(b, n, fillNameLower, func(items []fileInfo) {
				sort.Sort(byNameDirFirst(browseTemplateContext{Items: items}))
			})
		})
	}
}

func BenchmarkSortBySizeOld(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkSort(b, n, nil, func(items []fileInfo) {
				sort.Sort(bySizeOld(browseTemplateContext{Items: items}))
			})
		})
	}
}

func BenchmarkSortBySizeNew(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkSort(b, n, fillNameLower, func(items []fileInfo) {
				sort.Sort(bySize(browseTemplateContext{Items: items}))
			})
		})
	}
}

// ---------------------------------------------------------------------
// Overall benchmark: the whole real-world browse-request path - reading
// directory entries into a listing and then sorting it - old (directoryListingOld
// + applySortAndLimitOld) vs. new (directoryListing + applySortAndLimit).
// ---------------------------------------------------------------------

func benchmarkDirectoryListingAndSort(b *testing.B, n int, run func(fsrv *FileServer, ctx context.Context, fileSystem fs.FS, entries []fs.DirEntry, root string) *browseTemplateContext) {
	dir := b.TempDir()
	makeBenchDir(b, dir, n)
	fileSystem, entries := readBenchDirEntries(b, dir)
	fsrv := benchFileServer()
	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		run(fsrv, ctx, fileSystem, entries, dir)
	}
}

func BenchmarkDirectoryListingAndSortOld(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkDirectoryListingAndSort(b, n, func(fsrv *FileServer, ctx context.Context, fileSystem fs.FS, entries []fs.DirEntry, root string) *browseTemplateContext {
				listing := fsrv.directoryListingOld(ctx, fileSystem, time.Time{}, entries, true, root, "/", caddy.NewReplacer())
				listing.applySortAndLimitOld(sortByNameDirFirst, sortOrderAsc, "", "")
				return listing
			})
		})
	}
}

func BenchmarkDirectoryListingAndSortNew(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 50_000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			benchmarkDirectoryListingAndSort(b, n, func(fsrv *FileServer, ctx context.Context, fileSystem fs.FS, entries []fs.DirEntry, root string) *browseTemplateContext {
				listing := fsrv.directoryListing(ctx, fileSystem, time.Time{}, entries, true, root, "/", caddy.NewReplacer())
				listing.applySortAndLimit(sortByNameDirFirst, sortOrderAsc, "", "")
				return listing
			})
		})
	}
}
