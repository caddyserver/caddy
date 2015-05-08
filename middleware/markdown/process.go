package markdown

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/russross/blackfriday"
)

const (
	DefaultTemplate = "defaultTemplate"
	StaticDir       = ".caddy_static"
)

// process processes the contents of a page.
// It parses the metadata (if any) and uses the template (if found)
func (md Markdown) process(c Config, requestPath string, b []byte) ([]byte, error) {
	metadata, markdown, err := extractMetadata(b)
	if err != nil {
		return nil, err
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
	markdown = blackfriday.Markdown(markdown, c.Renderer, 0)

	// set it as body for template
	metadata.Variables["markdown"] = string(markdown)

	return md.processTemplate(c, requestPath, tmpl, metadata)
}

// processTemplate processes a template given a requestPath,
// template (tmpl) and metadata
func (md Markdown) processTemplate(c Config, requestPath string, tmpl []byte, metadata Metadata) ([]byte, error) {
	// if template is not specified,
	// use the default template
	if tmpl == nil {
		tmpl = defaultTemplate(c, metadata, requestPath)
	}

	// process the template
	b := &bytes.Buffer{}
	t, err := template.New("").Parse(string(tmpl))
	if err != nil {
		return nil, err
	}
	if err = t.Execute(b, metadata.Variables); err != nil {
		return nil, err
	}

	// generate static page
	if err = md.generatePage(c, requestPath, b.Bytes()); err != nil {
		// if static page generation fails,
		// nothing fatal, only log the error.
		log.Println(err)
	}

	return b.Bytes(), nil

}

// generatePage generates a static html page from the markdown in content.
func (md Markdown) generatePage(c Config, requestPath string, content []byte) error {
	// should not happen,
	// must be set on Markdown init.
	if c.StaticDir == "" {
		return fmt.Errorf("Static directory not set")
	}

	// if static directory is not existing, create it
	if _, err := os.Stat(c.StaticDir); err != nil {
		err := os.MkdirAll(c.StaticDir, os.FileMode(0755))
		if err != nil {
			return err
		}
	}

	filePath := filepath.Join(c.StaticDir, requestPath)

	// If it is index file, use the directory instead
	if md.IsIndexFile(filepath.Base(requestPath)) {
		filePath, _ = filepath.Split(filePath)
	}

	// Create the directory in case it is not existing
	if err := os.MkdirAll(filePath, os.FileMode(0755)); err != nil {
		return err
	}

	// generate index.html file in the directory
	filePath = filepath.Join(filePath, "index.html")
	err := ioutil.WriteFile(filePath, content, os.FileMode(0755))
	if err != nil {
		return err
	}

	c.StaticFiles[requestPath] = filePath
	return nil
}

// defaultTemplate constructs a default template.
func defaultTemplate(c Config, metadata Metadata, requestPath string) []byte {
	var scripts, styles bytes.Buffer
	for _, style := range c.Styles {
		styles.WriteString(strings.Replace(cssTemplate, "{{url}}", style, 1))
		styles.WriteString("\r\n")
	}
	for _, script := range c.Scripts {
		scripts.WriteString(strings.Replace(jsTemplate, "{{url}}", script, 1))
		scripts.WriteString("\r\n")
	}

	// Title is first line (length-limited), otherwise filename
	title := metadata.Title
	if title == "" {
		title = filepath.Base(requestPath)
		if body, _ := metadata.Variables["body"].([]byte); len(body) > 128 {
			title = string(body[:128])
		} else if len(body) > 0 {
			title = string(body)
		}
	}

	html := []byte(htmlTemplate)
	html = bytes.Replace(html, []byte("{{title}}"), []byte(title), 1)
	html = bytes.Replace(html, []byte("{{css}}"), styles.Bytes(), 1)
	html = bytes.Replace(html, []byte("{{js}}"), scripts.Bytes(), 1)

	return html
}

const (
	htmlTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{title}}</title>
		<meta charset="utf-8">
		{{css}}
		{{js}}
	</head>
	<body>
		{{.body}}
	</body>
</html>`
	cssTemplate = `<link rel="stylesheet" href="{{url}}">`
	jsTemplate  = `<script src="{{url}}"></script>`
)
