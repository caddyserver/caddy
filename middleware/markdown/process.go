package markdown

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"text/template"

	"github.com/mholt/caddy/middleware"
	"github.com/russross/blackfriday"
)

const (
	// DefaultTemplate is the default template.
	DefaultTemplate = "defaultTemplate"
)

// Data represents a markdown document.
type Data struct {
	middleware.Context
	Doc      map[string]string
	DocFlags map[string]bool
	Styles   []string
	Scripts  []string
}

// Include "overrides" the embedded middleware.Context's Include()
// method so that included files have access to d's fields.
func (d Data) Include(filename string) (string, error) {
	return middleware.ContextInclude(filename, d, d.Root)
}

// Process processes the contents of a page in b. It parses the metadata
// (if any) and uses the template (if found).
func (md Markdown) Process(c *Config, requestPath string, b []byte, ctx middleware.Context) ([]byte, error) {
	var metadata = newMetadata()
	var markdown []byte
	var err error

	// find parser compatible with page contents
	parser := findParser(b)

	if parser == nil {
		// if not found, assume whole file is markdown (no front matter)
		markdown = b
	} else {
		// if found, assume metadata present and parse.
		markdown, err = parser.Parse(b)
		if err != nil {
			return nil, err
		}
		metadata = parser.Metadata()
	}

	// if template is not specified, check if Default template is set
	if metadata.Template == "" {
		if _, ok := c.Templates[DefaultTemplate]; ok {
			metadata.Template = DefaultTemplate
		}
	}

	// if template is set, load it
	var tmpl []byte
	if metadata.Template != "" {
		if t, ok := c.Templates[metadata.Template]; ok {
			tmpl, err = ioutil.ReadFile(t)
		}
		if err != nil {
			return nil, err
		}
	}

	// process markdown
	extns := 0
	extns |= blackfriday.EXTENSION_TABLES
	extns |= blackfriday.EXTENSION_FENCED_CODE
	extns |= blackfriday.EXTENSION_STRIKETHROUGH
	extns |= blackfriday.EXTENSION_DEFINITION_LISTS
	markdown = blackfriday.Markdown(markdown, c.Renderer, extns)

	// set it as body for template
	metadata.Variables["body"] = string(markdown)
	title := metadata.Title
	if title == "" {
		title = filepath.Base(requestPath)
		var extension = filepath.Ext(requestPath)
		title = title[0 : len(title)-len(extension)]
	}
	metadata.Variables["title"] = title

	return md.processTemplate(c, requestPath, tmpl, metadata, ctx)
}

// processTemplate processes a template given a requestPath,
// template (tmpl) and metadata
func (md Markdown) processTemplate(c *Config, requestPath string, tmpl []byte, metadata Metadata, ctx middleware.Context) ([]byte, error) {
	var t *template.Template
	var err error

	// if template is not specified,
	// use the default template
	if tmpl == nil {
		t = template.Must(template.New("").Parse(htmlTemplate))
	} else {
		t, err = template.New("").Parse(string(tmpl))
		if err != nil {
			return nil, err
		}
	}

	// process the template
	mdData := Data{
		Context:  ctx,
		Doc:      metadata.Variables,
		DocFlags: metadata.Flags,
		Styles:   c.Styles,
		Scripts:  c.Scripts,
	}

	b := new(bytes.Buffer)
	err = t.Execute(b, mdData)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

const (
	htmlTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{.Doc.title}}</title>
		<meta charset="utf-8">
		{{range .Styles}}<link rel="stylesheet" href="{{.}}">
		{{end -}}
		{{range .Scripts}}<script src="{{.}}"></script>
		{{end -}}
	</head>
	<body>
		{{.Doc.body}}
	</body>
</html>`
)
