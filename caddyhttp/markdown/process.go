// Copyright 2015 Light Code Labs, LLC
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

package markdown

import (
	"io"
	"io/ioutil"
	"os"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/caddyserver/caddy/caddyhttp/markdown/metadata"
	"github.com/caddyserver/caddy/caddyhttp/markdown/summary"
	"github.com/russross/blackfriday"
)

// FileInfo represents a file in a particular server context. It wraps the os.FileInfo struct.
type FileInfo struct {
	os.FileInfo
	ctx httpserver.Context
}

var recognizedMetaTags = []string{
	"author",
	"copyright",
	"description",
	"subject",
}

// Summarize returns an abbreviated string representation of the markdown stored in this file.
// wordcount is the number of words returned in the summary.
func (f FileInfo) Summarize(wordcount int) (string, error) {
	fp, err := f.ctx.Root.Open(f.Name())
	if err != nil {
		return "", err
	}
	defer fp.Close()

	buf, err := ioutil.ReadAll(fp)
	if err != nil {
		return "", err
	}

	return string(summary.Markdown(buf, wordcount)), nil
}

// Markdown processes the contents of a page in b. It parses the metadata
// (if any) and uses the template (if found).
func (c *Config) Markdown(title string, r io.Reader, dirents []os.FileInfo, ctx httpserver.Context) ([]byte, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	parser := metadata.GetParser(body)
	markdown := parser.Markdown()
	mdata := parser.Metadata()

	// process markdown
	extns := 0
	extns |= blackfriday.EXTENSION_TABLES
	extns |= blackfriday.EXTENSION_FENCED_CODE
	extns |= blackfriday.EXTENSION_STRIKETHROUGH
	extns |= blackfriday.EXTENSION_DEFINITION_LISTS
	html := blackfriday.Markdown(markdown, c.Renderer, extns)

	// set it as body for template
	mdata.Variables["body"] = string(html)

	// fixup title
	mdata.Variables["title"] = mdata.Title
	if mdata.Variables["title"] == "" {
		mdata.Variables["title"] = title
	}

	// move available and valid front matters to the meta values
	meta := make(map[string]string)
	for _, val := range recognizedMetaTags {
		if mVal, ok := mdata.Variables[val]; ok {
			meta[val] = mVal.(string)
		}
	}

	// massage possible files
	files := []FileInfo{}
	for _, ent := range dirents {
		file := FileInfo{
			FileInfo: ent,
			ctx:      ctx,
		}
		files = append(files, file)
	}

	return execTemplate(c, mdata, meta, files, ctx)
}
