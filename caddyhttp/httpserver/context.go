package httpserver

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/russross/blackfriday"
	"os"
)

// This file contains the context and functions available for
// use in the templates.

// Context is the context with which Caddy templates are executed.
type Context struct {
	Root http.FileSystem
	Req  *http.Request
	URL  *url.URL
}

// Include returns the contents of filename relative to the site root.
func (c Context) Include(filename string) (string, error) {
	return ContextInclude(filename, c, c.Root)
}

// Now returns the current timestamp in the specified format.
func (c Context) Now(format string) string {
	return time.Now().Format(format)
}

// NowDate returns the current date/time that can be used
// in other time functions.
func (c Context) NowDate() time.Time {
	return time.Now()
}

// Cookie gets the value of a cookie with name name.
func (c Context) Cookie(name string) string {
	cookies := c.Req.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// Header gets the value of a request header with field name.
func (c Context) Header(name string) string {
	return c.Req.Header.Get(name)
}

// Env gets a map of the environment variables.
func (c Context) Env() map[string]string {
	osEnv := os.Environ()
	envVars := make(map[string]string, len(osEnv))
	for _, env := range osEnv {
		data := strings.SplitN(env, "=", 2)
		if len(data) == 2 && len(data[0]) > 0 {
			envVars[data[0]] = data[1]
		}
	}
	return envVars
}

// IP gets the (remote) IP address of the client making the request.
func (c Context) IP() string {
	ip, _, err := net.SplitHostPort(c.Req.RemoteAddr)
	if err != nil {
		return c.Req.RemoteAddr
	}
	return ip
}

// URI returns the raw, unprocessed request URI (including query
// string and hash) obtained directly from the Request-Line of
// the HTTP request.
func (c Context) URI() string {
	return c.Req.RequestURI
}

// Host returns the hostname portion of the Host header
// from the HTTP request.
func (c Context) Host() (string, error) {
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

// Port returns the port portion of the Host header if specified.
func (c Context) Port() (string, error) {
	_, port, err := net.SplitHostPort(c.Req.Host)
	if err != nil {
		if !strings.Contains(c.Req.Host, ":") {
			// common with sites served on the default port 80
			return "80", nil
		}
		return "", err
	}
	return port, nil
}

// Method returns the method (GET, POST, etc.) of the request.
func (c Context) Method() string {
	return c.Req.Method
}

// PathMatches returns true if the path portion of the request
// URL matches pattern.
func (c Context) PathMatches(pattern string) bool {
	return Path(c.Req.URL.Path).Matches(pattern)
}

// Truncate truncates the input string to the given length.
// If length is negative, it returns that many characters
// starting from the end of the string. If the absolute value
// of length is greater than len(input), the whole input is
// returned.
func (c Context) Truncate(input string, length int) string {
	if length < 0 && len(input)+length > 0 {
		return input[len(input)+length:]
	}
	if length >= 0 && len(input) > length {
		return input[:length]
	}
	return input
}

// StripHTML returns s without HTML tags. It is fairly naive
// but works with most valid HTML inputs.
func (c Context) StripHTML(s string) string {
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

// Ext returns the suffix beginning at the final dot in the final
// slash-separated element of the pathStr (or in other words, the
// file extension).
func (c Context) Ext(pathStr string) string {
	return path.Ext(pathStr)
}

// StripExt returns the input string without the extension,
// which is the suffix starting with the final '.' character
// but not before the final path separator ('/') character.
// If there is no extension, the whole input is returned.
func (c Context) StripExt(path string) string {
	for i := len(path) - 1; i >= 0 && path[i] != '/'; i-- {
		if path[i] == '.' {
			return path[:i]
		}
	}
	return path
}

// Replace replaces instances of find in input with replacement.
func (c Context) Replace(input, find, replacement string) string {
	return strings.Replace(input, find, replacement, -1)
}

// Markdown returns the HTML contents of the markdown contained in filename
// (relative to the site root).
func (c Context) Markdown(filename string) (string, error) {
	body, err := c.Include(filename)
	if err != nil {
		return "", err
	}
	renderer := blackfriday.HtmlRenderer(0, "", "")
	extns := 0
	extns |= blackfriday.EXTENSION_TABLES
	extns |= blackfriday.EXTENSION_FENCED_CODE
	extns |= blackfriday.EXTENSION_STRIKETHROUGH
	extns |= blackfriday.EXTENSION_DEFINITION_LISTS
	markdown := blackfriday.Markdown([]byte(body), renderer, extns)

	return string(markdown), nil
}

// ContextInclude opens filename using fs and executes a template with the context ctx.
// This does the same thing that Context.Include() does, but with the ability to provide
// your own context so that the included files can have access to additional fields your
// type may provide. You can embed Context in your type, then override its Include method
// to call this function with ctx being the instance of your type, and fs being Context.Root.
func ContextInclude(filename string, ctx interface{}, fs http.FileSystem) (string, error) {
	file, err := fs.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	tpl, err := template.New(filename).Parse(string(body))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tpl.Execute(&buf, ctx)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// ToLower will convert the given string to lower case.
func (c Context) ToLower(s string) string {
	return strings.ToLower(s)
}

// ToUpper will convert the given string to upper case.
func (c Context) ToUpper(s string) string {
	return strings.ToUpper(s)
}

// Split is a pass-through to strings.Split. It will split the first argument at each instance of the separator and return a slice of strings.
func (c Context) Split(s string, sep string) []string {
	return strings.Split(s, sep)
}

// Join is a pass-through to strings.Join. It will join the first argument slice with the separator in the second argument and return the result.
func (c Context) Join(a []string, sep string) string {
	return strings.Join(a, sep)
}

// Slice will convert the given arguments into a slice.
func (c Context) Slice(elems ...interface{}) []interface{} {
	return elems
}

// Map will convert the arguments into a map. It expects alternating string keys and values. This is useful for building more complicated data structures
// if you are using subtemplates or things like that.
func (c Context) Map(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("Map expects an even number of arguments")
	}
	dict := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("Map keys must be strings")
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

// Files reads and returns a slice of names from the given directory
// relative to the root of Context c.
func (c Context) Files(name string) ([]string, error) {
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
