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
	"io/fs"
	"testing"
	"time"
)

type benchFileInfo struct {
	size  int64
	mtime time.Time
}

func (fi benchFileInfo) Name() string       { return "file.txt" }
func (fi benchFileInfo) Size() int64        { return fi.size }
func (fi benchFileInfo) Mode() fs.FileMode  { return 0o644 }
func (fi benchFileInfo) ModTime() time.Time { return fi.mtime }
func (fi benchFileInfo) IsDir() bool        { return false }
func (fi benchFileInfo) Sys() any           { return nil }

func BenchmarkCalculateEtag(b *testing.B) {
	fi := benchFileInfo{size: 1234567, mtime: time.Unix(1700000000, 123456789)}
	b.ReportAllocs()
	for b.Loop() {
		_ = calculateEtag(fi)
	}
}
