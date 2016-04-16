package markdown

import (
	"path/filepath"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/markdown/metadata"
	"github.com/russross/blackfriday"
)

// Markdown processes the contents of a page in b. It parses the metadata
// (if any) and uses the template (if found).
func (c *Config) Markdown(requestPath string, b []byte, ctx middleware.Context) ([]byte, error) {
	parser := metadata.GetParser(b)
	markdown := parser.Markdown()
	mdata := parser.Metadata()

	// process markdown
	extns := 0
	extns |= blackfriday.EXTENSION_TABLES
	extns |= blackfriday.EXTENSION_FENCED_CODE
	extns |= blackfriday.EXTENSION_STRIKETHROUGH
	extns |= blackfriday.EXTENSION_DEFINITION_LISTS
	markdown = blackfriday.Markdown(markdown, c.Renderer, extns)

	// set it as body for template
	mdata.Variables["body"] = string(markdown)
	title := mdata.Title
	if title == "" {
		title = filepath.Base(requestPath)
		var extension = filepath.Ext(requestPath)
		title = title[0 : len(title)-len(extension)]
	}
	mdata.Variables["title"] = title

	return execTemplate(c, mdata, ctx)
}
