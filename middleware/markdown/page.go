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

const (
	// Date format YYYY-MM-DD HH:MM:SS
	timeLayout = `2006-01-02 15:04:05`

	// Length of page summary.
	summaryLen = 150
)

// PageLink represents a statically generated markdown page.
type PageLink struct {
	Title   string
	Summary string
	Date    time.Time
	Url     string
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

func (l *linkGen) generateLinks(md Markdown, cfg *Config) {
	l.Lock()
	l.generating = true
	l.Unlock()

	fp := filepath.Join(md.Root, cfg.PathScope)

	cfg.Links = []PageLink{}

	cfg.Lock()
	l.lastErr = filepath.Walk(fp, func(path string, info os.FileInfo, err error) error {
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

		return nil
	})

	// sort by newest date
	sort.Sort(byDate(cfg.Links))
	cfg.Unlock()

	l.Lock()
	l.generating = false
	l.Unlock()
}

type linkGenerator struct {
	gens map[*Config]*linkGen
	sync.Mutex
}

var generator = linkGenerator{gens: make(map[*Config]*linkGen)}

// GenerateLinks generates links to all markdown files ordered by newest date.
// This blocks until link generation is done. When called by multiple goroutines,
// the first caller starts the generation and others only wait.
func GenerateLinks(md Markdown, cfg *Config) error {
	generator.Lock()

	// if link generator exists for config and running, wait.
	if g, ok := generator.gens[cfg]; ok {
		if g.started() {
			g.addWaiter()
			generator.Unlock()
			g.Wait()
			return g.lastErr
		}
	}

	g := &linkGen{}
	generator.gens[cfg] = g
	generator.Unlock()

	g.generateLinks(md, cfg)
	g.discardWaiters()
	return g.lastErr
}
