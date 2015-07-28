package markdown

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/russross/blackfriday"
)

var (
	pagesMutex      sync.RWMutex
	linksGenerating bool
)

const (
	timeLayout = `2006-01-02 15:04:05`
	summaryLen = 150
)

// Page represents a statically generated markdown page.
type PageLink struct {
	Title   string
	Summary string
	Date    time.Time
	Url     string
}

// pageLinkSorter sort PageLink by newest date to oldest.
type pageLinkSorter []PageLink

func (p pageLinkSorter) Len() int           { return len(p) }
func (p pageLinkSorter) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p pageLinkSorter) Less(i, j int) bool { return p[i].Date.After(p[j].Date) }

func GenerateLinks(md Markdown, cfg *Config) error {
	if linksGenerating {
		return nil
	}

	pagesMutex.Lock()
	linksGenerating = true

	fp := filepath.Join(md.Root, cfg.PathScope)

	cfg.Links = []PageLink{}
	err := filepath.Walk(fp, func(path string, info os.FileInfo, err error) error {
		for _, ext := range cfg.Extensions {
			if !info.IsDir() && strings.HasSuffix(info.Name(), ext) {
				// Load the file
				body, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}

				// Get the relative path as if it were a HTTP request,
				// then prepend with "/" (like a real HTTP request)
				reqPath, err := filepath.Rel(md.Root, path)
				if err != nil {
					return err
				}
				reqPath = "/" + reqPath

				parser := findParser(body)
				if parser == nil {
					// no metadata, ignore.
					continue
				}
				summary, err := parser.Parse(body)
				if err != nil {
					return err
				}

				if len(summary) > summaryLen {
					summary = summary[:summaryLen]
				}

				metadata := parser.Metadata()

				cfg.Links = append(cfg.Links, PageLink{
					Title:   metadata.Title,
					Url:     reqPath,
					Date:    metadata.Date,
					Summary: string(blackfriday.Markdown(summary, PlaintextRenderer{}, 0)),
				})

				break // don't try other file extensions
			}
		}

		// sort by newest date
		sort.Sort(pageLinkSorter(cfg.Links))
		return nil
	})

	linksGenerating = false
	pagesMutex.Unlock()
	return err
}
