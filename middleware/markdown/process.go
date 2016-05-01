package markdown

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/markdown/metadata"
	"github.com/mholt/caddy/middleware/markdown/summary"
	"github.com/russross/blackfriday"
)

type FileInfo struct {
	os.FileInfo
	ctx middleware.Context
}

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
func (c *Config) Markdown(requestPath string, b []byte, dirents []os.FileInfo, ctx middleware.Context) ([]byte, error) {
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

	// fixup title
	title := mdata.Title
	if title == "" {
		title = filepath.Base(requestPath)
		var extension = filepath.Ext(requestPath)
		title = title[0 : len(title)-len(extension)]
	}
	mdata.Variables["title"] = title

	// massage possible files
	files := []FileInfo{}
	for _, ent := range dirents {
		file := FileInfo{
			FileInfo: ent,
			ctx:      ctx,
		}
		files = append(files, file)
	}

	return execTemplate(c, mdata, files, ctx)
}
