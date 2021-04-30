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
	"testing"
	"text/template"
)

func BenchmarkBrowseWriteJSON(b *testing.B) {
	fsrv := new(FileServer)
	listing := browseTemplateContext{
		Name:     "test",
		Path:     "test",
		CanGoUp:  false,
		Items:    make([]fileInfo, 100),
		NumDirs:  42,
		NumFiles: 420,
		Sort:     "",
		Order:    "",
		Limit:    42,
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		fsrv.browseWriteJSON(listing)
	}
}

func BenchmarkBrowseWriteHTML(b *testing.B) {
	fsrv := new(FileServer)
	fsrv.Browse = &Browse{
		TemplateFile: "",
		template:     template.New("test"),
	}
	listing := browseTemplateContext{
		Name:     "test",
		Path:     "test",
		CanGoUp:  false,
		Items:    make([]fileInfo, 100),
		NumDirs:  42,
		NumFiles: 420,
		Sort:     "",
		Order:    "",
		Limit:    42,
	}
	tplCtx := templateContext{
		browseTemplateContext: listing,
	}
	fsrv.browseParseTemplate(&tplCtx)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		fsrv.browseWriteHTML(&tplCtx)
	}
}
