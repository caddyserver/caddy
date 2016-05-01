package markdown

import (
	"bytes"
	"io/ioutil"
	// "os"
	"text/template"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/markdown/metadata"
)

// Data represents a markdown document.
type Data struct {
	middleware.Context
	Doc      map[string]string
	DocFlags map[string]bool
	Styles   []string
	Scripts  []string
	Files    []FileInfo
}

// Include "overrides" the embedded middleware.Context's Include()
// method so that included files have access to d's fields.
// Note: using {{template 'template-name' .}} instead might be better.
func (d Data) Include(filename string) (string, error) {
	return middleware.ContextInclude(filename, d, d.Root)
}

// execTemplate executes a template given a requestPath, template, and metadata
func execTemplate(c *Config, mdata metadata.Metadata, files []FileInfo, ctx middleware.Context) ([]byte, error) {
	mdData := Data{
		Context:  ctx,
		Doc:      mdata.Variables,
		DocFlags: mdata.Flags,
		Styles:   c.Styles,
		Scripts:  c.Scripts,
		Files:    files,
	}

	b := new(bytes.Buffer)
	if err := c.Template.ExecuteTemplate(b, mdata.Template, mdData); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func setDefaultTemplate(filename string) *template.Template {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}

	return template.Must(GetDefaultTemplate().Parse(string(buf)))
}

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

func GetDefaultTemplate() *template.Template {
	return template.Must(template.New("").Parse(defaultTemplate))
}

const (
	defaultTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{.Doc.title}}</title>
		<meta charset="utf-8">
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
