package markdown

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/russross/blackfriday"
)

const (
	// Date format YYYY-MM-DD HH:MM:SS
	timeLayout = `2006-01-02 15:04:05`

	// Maximum length of page summary.
	summaryLen = 500
)

// PageLink represents a statically generated markdown page.
type PageLink struct {
	Title   string
	Summary string
	Date    time.Time
	URL     string
}

// byDate sorts PageLink by newest date to oldest.
type byDate []PageLink

func (p byDate) Len() int           { return len(p) }
func (p byDate) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p byDate) Less(i, j int) bool { return p[i].Date.After(p[j].Date) }

type linkGen struct {
	generating bool
	waiters    int
	lastErr    error
	sync.RWMutex
	sync.WaitGroup
}

func (l *linkGen) addWaiter() {
	l.WaitGroup.Add(1)
	l.waiters++
}

func (l *linkGen) discardWaiters() {
	l.Lock()
	defer l.Unlock()
	for i := 0; i < l.waiters; i++ {
		l.Done()
	}
}

func (l *linkGen) started() bool {
	l.RLock()
	defer l.RUnlock()
	return l.generating
}

// generateLinks generate links to markdown files if there are file changes.
// It returns true when generation is done and false otherwise.
func (l *linkGen) generateLinks(md Markdown, cfg *Config) bool {
	l.Lock()
	l.generating = true
	l.Unlock()

	fp := filepath.Join(md.Root, cfg.PathScope) // path to scan for .md files

	// If the file path to scan for Markdown files (fp) does
	// not exist, there are no markdown files to scan for.
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		l.Lock()
		l.lastErr = err
		l.generating = false
		l.Unlock()
		return false
	}

	hash, err := computeDirHash(md, *cfg)

	// same hash, return.
	if err == nil && hash == cfg.linksHash {
		l.Lock()
		l.generating = false
		l.Unlock()
		return false
	} else if err != nil {
		log.Println("Hash error (markdown):", err)
	}

	cfg.Links = []PageLink{}

	cfg.Lock()
	l.lastErr = filepath.Walk(fp, func(path string, info os.FileInfo, err error) error {
		for _, ext := range cfg.Extensions {
			if info.IsDir() || !strings.HasSuffix(info.Name(), ext) {
				continue
			}

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

			// truncate summary to maximum length
			if len(summary) > summaryLen {
				summary = summary[:summaryLen]

				// trim to nearest word
				lastSpace := bytes.LastIndex(summary, []byte(" "))
				if lastSpace != -1 {
					summary = summary[:lastSpace]
				}
			}

			metadata := parser.Metadata()

			cfg.Links = append(cfg.Links, PageLink{
				Title:   metadata.Title,
				URL:     reqPath,
				Date:    metadata.Date,
				Summary: string(blackfriday.Markdown(summary, SummaryRenderer{}, 0)),
			})

			break // don't try other file extensions
		}

		return nil
	})

	// sort by newest date
	sort.Sort(byDate(cfg.Links))

	cfg.linksHash = hash
	cfg.Unlock()

	l.Lock()
	l.generating = false
	l.Unlock()
	return true
}
