// Copyright 2015 Matthew Holt and The Caddy Authors
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

package templates

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/alecthomas/chroma/formatters/html"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
)

// templateContext is the templateContext with which HTTP templates are executed.
type templateContext struct {
	Root       http.FileSystem
	Req        *http.Request
	Args       []interface{} // defined by arguments to .Include
	RespHeader tplWrappedHeader

	config *Templates
}

// OriginalReq returns the original, unmodified, un-rewritten request as
// it originally came in over the wire.
func (c templateContext) OriginalReq() http.Request {
	or, _ := c.Req.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
	return or
}

// funcInclude returns the contents of filename relative to the site root.
// Note that included files are NOT escaped, so you should only include
// trusted files. If it is not trusted, be sure to use escaping functions
// in your template.
func (c templateContext) funcInclude(filename string, args ...interface{}) (string, error) {
	if c.Root == nil {
		return "", fmt.Errorf("root file system not specified")
	}

	file, err := c.Root.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	bodyBuf := bufPool.Get().(*bytes.Buffer)
	bodyBuf.Reset()
	defer bufPool.Put(bodyBuf)

	_, err = io.Copy(bodyBuf, file)
	if err != nil {
		return "", err
	}

	c.Args = args

	err = c.executeTemplateInBuffer(filename, bodyBuf)
	if err != nil {
		return "", err
	}

	return bodyBuf.String(), nil
}

// funcHTTPInclude returns the body of a virtual (lightweight) request
// to the given URI on the same server. Note that included bodies
// are NOT escaped, so you should only include trusted resources.
// If it is not trusted, be sure to use escaping functions yourself.
func (c templateContext) funcHTTPInclude(uri string) (string, error) {
	// prevent virtual request loops by counting how many levels
	// deep we are; and if we get too deep, return an error
	recursionCount := 1
	if numStr := c.Req.Header.Get(recursionPreventionHeader); numStr != "" {
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return "", fmt.Errorf("parsing %s: %v", recursionPreventionHeader, err)
		}
		if num >= 3 {
			return "", fmt.Errorf("virtual request cycle")
		}
		recursionCount = num + 1
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	virtReq, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", err
	}
	virtReq.Host = c.Req.Host
	virtReq.Header = c.Req.Header.Clone()
	virtReq.Trailer = c.Req.Trailer.Clone()
	virtReq.Header.Set(recursionPreventionHeader, strconv.Itoa(recursionCount))

	vrw := &virtualResponseWriter{body: buf, header: make(http.Header)}
	server := c.Req.Context().Value(caddyhttp.ServerCtxKey).(http.Handler)

	server.ServeHTTP(vrw, virtReq)
	if vrw.status >= 400 {
		return "", fmt.Errorf("http %d", vrw.status)
	}

	err = c.executeTemplateInBuffer(uri, buf)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (c templateContext) executeTemplateInBuffer(tplName string, buf *bytes.Buffer) error {
	tpl := template.New(tplName)
	if len(c.config.Delimiters) == 2 {
		tpl.Delims(c.config.Delimiters[0], c.config.Delimiters[1])
	}

	tpl.Funcs(sprigFuncMap)

	tpl.Funcs(template.FuncMap{
		"include":          c.funcInclude,
		"httpInclude":      c.funcHTTPInclude,
		"stripHTML":        c.funcStripHTML,
		"markdown":         c.funcMarkdown,
		"splitFrontMatter": c.funcSplitFrontMatter,
		"listFiles":        c.funcListFiles,
		"env":              c.funcEnv,
	})

	parsedTpl, err := tpl.Parse(buf.String())
	if err != nil {
		return err
	}

	buf.Reset() // reuse buffer for output

	return parsedTpl.Execute(buf, c)
}

func (templateContext) funcEnv(varName string) string {
	return os.Getenv(varName)
}

// Cookie gets the value of a cookie with name name.
func (c templateContext) Cookie(name string) string {
	cookies := c.Req.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// RemoteIP gets the IP address of the client making the request.
func (c templateContext) RemoteIP() string {
	ip, _, err := net.SplitHostPort(c.Req.RemoteAddr)
	if err != nil {
		return c.Req.RemoteAddr
	}
	return ip
}

// Host returns the hostname portion of the Host header
// from the HTTP request.
func (c templateContext) Host() (string, error) {
	host, _, err := net.SplitHostPort(c.Req.Host)
	if err != nil {
		if !strings.Contains(c.Req.Host, ":") {
			// common with sites served on the default port 80
			return c.Req.Host, nil
		}
		return "", err
	}
	return host, nil
}

// funcStripHTML returns s without HTML tags. It is fairly naive
// but works with most valid HTML inputs.
func (templateContext) funcStripHTML(s string) string {
	var buf bytes.Buffer
	var inTag, inQuotes bool
	var tagStart int
	for i, ch := range s {
		if inTag {
			if ch == '>' && !inQuotes {
				inTag = false
			} else if ch == '<' && !inQuotes {
				// false start
				buf.WriteString(s[tagStart:i])
				tagStart = i
			} else if ch == '"' {
				inQuotes = !inQuotes
			}
			continue
		}
		if ch == '<' {
			inTag = true
			tagStart = i
			continue
		}
		buf.WriteRune(ch)
	}
	if inTag {
		// false start
		buf.WriteString(s[tagStart:])
	}
	return buf.String()
}

// funcMarkdown renders the markdown body as HTML. The resulting
// HTML is NOT escaped so that it can be rendered as HTML.
func (templateContext) funcMarkdown(input interface{}) (string, error) {
	inputStr := toString(input)

	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.Footnote,
			highlighting.NewHighlighting(
				highlighting.WithFormatOptions(
					html.WithClasses(true),
				),
			),
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			gmhtml.WithHardWraps(),
			gmhtml.WithUnsafe(), // TODO: this is not awesome, maybe should be configurable?
		),
	)

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	md.Convert([]byte(inputStr), buf)

	return buf.String(), nil
}

// splitFrontMatter parses front matter out from the beginning of input,
// and returns the separated key-value pairs and the body/content. input
// must be a "stringy" value.
func (templateContext) funcSplitFrontMatter(input interface{}) (parsedMarkdownDoc, error) {
	meta, body, err := extractFrontMatter(toString(input))
	if err != nil {
		return parsedMarkdownDoc{}, err
	}
	return parsedMarkdownDoc{Meta: meta, Body: body}, nil
}

// funcListFiles reads and returns a slice of names from the given
// directory relative to the root of c.
func (c templateContext) funcListFiles(name string) ([]string, error) {
	if c.Root == nil {
		return nil, fmt.Errorf("root file system not specified")
	}

	dir, err := c.Root.Open(path.Clean(name))
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	stat, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("%v is not a directory", name)
	}

	dirInfo, err := dir.Readdir(0)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(dirInfo))
	for i, fileInfo := range dirInfo {
		names[i] = fileInfo.Name()
	}

	return names, nil
}

// tplWrappedHeader wraps niladic functions so that they
// can be used in templates. (Template functions must
// return a value.)
type tplWrappedHeader struct{ http.Header }

// Add adds a header field value, appending val to
// existing values for that field. It returns an
// empty string.
func (h tplWrappedHeader) Add(field, val string) string {
	h.Header.Add(field, val)
	return ""
}

// Set sets a header field value, overwriting any
// other values for that field. It returns an
// empty string.
func (h tplWrappedHeader) Set(field, val string) string {
	h.Header.Set(field, val)
	return ""
}

// Del deletes a header field. It returns an empty string.
func (h tplWrappedHeader) Del(field string) string {
	h.Header.Del(field)
	return ""
}

func toString(input interface{}) string {
	switch v := input.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case error:
		return v.Error()
	default:
		return fmt.Sprintf("%v", input)
	}
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// at time of writing, sprig.FuncMap() makes a copy, thus
// involves iterating the whole map, so do it just once
var sprigFuncMap = sprig.TxtFuncMap()

const recursionPreventionHeader = "Caddy-Templates-Include"
