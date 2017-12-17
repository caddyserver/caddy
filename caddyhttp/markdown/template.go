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
	"bytes"
	"io/ioutil"
	"os"
	"sync"
	"text/template"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/markdown/metadata"
)

// Data represents a markdown document.
type Data struct {
	httpserver.Context
	Doc     map[string]interface{}
	Styles  []string
	Scripts []string
	Meta    map[string]string
	Files   []FileInfo
}

// Include "overrides" the embedded httpserver.Context's Include()
// method so that included files have access to d's fields.
// Note: using {{template 'template-name' .}} instead might be better.
func (d Data) Include(filename string, args ...interface{}) (string, error) {
	d.Args = args
	return httpserver.ContextInclude(filename, d, d.Root)
}

var templateUpdateMu sync.RWMutex

// execTemplate executes a template given a requestPath, template, and metadata
func execTemplate(c *Config, mdata metadata.Metadata, meta map[string]string, files []FileInfo, ctx httpserver.Context) ([]byte, error) {
	mdData := Data{
		Context: ctx,
		Doc:     mdata.Variables,
		Styles:  c.Styles,
		Scripts: c.Scripts,
		Meta:    meta,
		Files:   files,
	}
	templateName := mdata.Template

	updateTemplate := func() error {
		templateUpdateMu.Lock()
		defer templateUpdateMu.Unlock()

		templateFile, ok := c.TemplateFiles[templateName]
		if !ok {
			return nil
		}

		currentFileInfo, err := os.Lstat(templateFile.path)
		if err != nil {
			return err
		}

		if !fileChanged(currentFileInfo, templateFile.fi) {
			return nil
		}

		// update template due to file changes
		err = SetTemplate(c.Template, templateName, templateFile.path)
		if err != nil {
			return err
		}

		templateFile.fi = currentFileInfo
		return nil
	}

	if err := updateTemplate(); err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	templateUpdateMu.RLock()
	defer templateUpdateMu.RUnlock()
	if err := c.Template.ExecuteTemplate(b, templateName, mdData); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func fileChanged(new, old os.FileInfo) bool {
	// never checked before
	if old == nil {
		return true
	}

	if new.Size() != old.Size() ||
		new.Mode() != old.Mode() ||
		new.ModTime() != old.ModTime() {
		return true
	}

	return false
}

// SetTemplate reads in the template with the filename provided. If the file does not exist or is not parsable, it will return an error.
func SetTemplate(t *template.Template, name, filename string) error {

	// Read template
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	// Update if exists
	if tt := t.Lookup(name); tt != nil {
		_, err = tt.Parse(string(buf))
		return err
	}

	// Allocate new name if not
	_, err = t.New(name).Parse(string(buf))
	return err
}

// GetDefaultTemplate returns the default template.
func GetDefaultTemplate() *template.Template {
	return template.Must(template.New("").Parse(defaultTemplate))
}

const (
	defaultTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{.Doc.title}}</title>
		<meta charset="utf-8">
		{{range $key, $val := .Meta}}
		<meta name="{{$key}}" content="{{$val}}">
		{{end}}
		{{- range .Styles}}
		<link rel="stylesheet" href="{{.}}">
		{{- end}}
		{{- range .Scripts}}
		<script src="{{.}}"></script>
		{{- end}}
	</head>
	<body>
		{{.Doc.body}}
	</body>
</html>`
)
