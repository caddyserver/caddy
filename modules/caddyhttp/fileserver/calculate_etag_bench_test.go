package fileserver

import (
	"io/fs"
	"testing"
	"time"
)

type benchFileInfo struct {
	size  int64
	mtime time.Time
}

func (fi benchFileInfo) Name() string       { return "file.txt" }
func (fi benchFileInfo) Size() int64         { return fi.size }
func (fi benchFileInfo) Mode() fs.FileMode   { return 0o644 }
func (fi benchFileInfo) ModTime() time.Time  { return fi.mtime }
func (fi benchFileInfo) IsDir() bool         { return false }
func (fi benchFileInfo) Sys() any            { return nil }

func BenchmarkCalculateEtag(b *testing.B) {
	fi := benchFileInfo{size: 1234567, mtime: time.Unix(1700000000, 123456789)}
	b.ReportAllocs()
	for b.Loop() {
		_ = calculateEtag(fi)
	}
}
