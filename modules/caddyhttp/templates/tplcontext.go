package templates

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	weakrand "math/rand"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"text/template"
	"time"

	"os"

	"github.com/caddyserver/caddy/modules/caddyhttp"
	"gopkg.in/russross/blackfriday.v2"
)

// templateContext is the templateContext with which HTTP templates are executed.
type templateContext struct {
	Root       http.FileSystem
	Req        *http.Request
	Args       []interface{} // defined by arguments to .Include
	RespHeader tplWrappedHeader
	server     http.Handler
}

// Include returns the contents of filename relative to the site root.
func (c templateContext) Include(filename string, args ...interface{}) (string, error) {
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

	return c.executeTemplate(filename, bodyBuf.Bytes())
}

// HTTPInclude returns the body of a virtual (lightweight) request
// to the given URI on the same server.
func (c templateContext) HTTPInclude(uri string) (string, error) {
	if c.Req.Header.Get(recursionPreventionHeader) == "1" {
		return "", fmt.Errorf("virtual include cycle")
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	virtReq, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", err
	}
	virtReq.Header.Set(recursionPreventionHeader, "1")

	vrw := &virtualResponseWriter{body: buf, header: make(http.Header)}
	server := c.Req.Context().Value(caddyhttp.ServerCtxKey).(http.Handler)

	server.ServeHTTP(vrw, virtReq)
	if vrw.status >= 400 {
		return "", fmt.Errorf("http %d", vrw.status)
	}

	return c.executeTemplate(uri, buf.Bytes())
}

func (c templateContext) executeTemplate(tplName string, body []byte) (string, error) {
	tpl, err := template.New(tplName).Parse(string(body))
	if err != nil {
		return "", err
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	err = tpl.Execute(buf, c)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Now returns the current timestamp.
func (c templateContext) Now() time.Time {
	return time.Now()
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

// ReqHeader gets the value of a request header with field name.
func (c templateContext) ReqHeader(name string) string {
	return c.Req.Header.Get(name)
}

// Hostname gets the (remote) hostname of the client making the request.
func (c templateContext) Hostname() string {
	ip := c.IP()

	hostnameList, err := net.LookupAddr(ip)
	if err != nil || len(hostnameList) == 0 {
		return c.Req.RemoteAddr
	}

	return hostnameList[0]
}

// Env gets a map of the environment variables.
func (c templateContext) Env() map[string]string {
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
func (c templateContext) IP() string {
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

// Truncate truncates the input string to the given length.
// If length is negative, it returns that many characters
// starting from the end of the string. If the absolute value
// of length is greater than len(input), the whole input is
// returned.
func (c templateContext) Truncate(input string, length int) string {
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
func (c templateContext) StripHTML(s string) string {
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

// Markdown renders the markdown body as HTML.
func (c templateContext) Markdown(body string) string {
	return string(blackfriday.Run([]byte(body)))
}

// Ext returns the suffix beginning at the final dot in the final
// slash-separated element of the pathStr (or in other words, the
// file extension).
func (c templateContext) Ext(pathStr string) string {
	return path.Ext(pathStr)
}

// StripExt returns the input string without the extension,
// which is the suffix starting with the final '.' character
// but not before the final path separator ('/') character.
// If there is no extension, the whole input is returned.
func (c templateContext) StripExt(path string) string {
	for i := len(path) - 1; i >= 0 && path[i] != '/'; i-- {
		if path[i] == '.' {
			return path[:i]
		}
	}
	return path
}

// Replace replaces instances of find in input with replacement.
func (c templateContext) Replace(input, find, replacement string) string {
	return strings.Replace(input, find, replacement, -1)
}

// HasPrefix returns true if s starts with prefix.
func (c templateContext) HasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// ToLower will convert the given string to lower case.
func (c templateContext) ToLower(s string) string {
	return strings.ToLower(s)
}

// ToUpper will convert the given string to upper case.
func (c templateContext) ToUpper(s string) string {
	return strings.ToUpper(s)
}

// Split is a pass-through to strings.Split. It will split
// the first argument at each instance of the separator and
// return a slice of strings.
func (c templateContext) Split(s string, sep string) []string {
	return strings.Split(s, sep)
}

// Join is a pass-through to strings.Join. It will join the
// first argument slice with the separator in the second
// argument and return the result.
func (c templateContext) Join(a []string, sep string) string {
	return strings.Join(a, sep)
}

// Slice will convert the given arguments into a slice.
func (c templateContext) Slice(elems ...interface{}) []interface{} {
	return elems
}

// Dict will convert the arguments into a dictionary (map). It expects
// alternating keys and values of string types. This is useful since you
// cannot express map literals directly in Go templates.
func (c templateContext) Dict(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("expected even number of arguments")
	}
	dict := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("argument %d: map keys must be strings", i)
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

// ListFiles reads and returns a slice of names from the given
// directory relative to the root of c.
func (c templateContext) ListFiles(name string) ([]string, error) {
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

// RandomString generates a random string of random length given
// length bounds. Thanks to http://stackoverflow.com/a/35615565/1048862
// for the clever technique that is fairly fast, secure, and maintains
// proper distributions over the dictionary.
func (c templateContext) RandomString(minLen, maxLen int) string {
	const (
		letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		letterIdxBits = 6                    // 6 bits to represent 64 possibilities (indexes)
		letterIdxMask = 1<<letterIdxBits - 1 // all 1-bits, as many as letterIdxBits
	)

	if minLen < 0 || maxLen < 0 || maxLen < minLen {
		return ""
	}

	n := weakrand.Intn(maxLen-minLen+1) + minLen // choose actual length

	// secureRandomBytes returns a number of bytes using crypto/rand.
	secureRandomBytes := func(numBytes int) []byte {
		randomBytes := make([]byte, numBytes)
		if _, err := rand.Read(randomBytes); err != nil {
			// TODO: what to do with the logs (throughout whole file) (could return as error? might get rendered though...)
			log.Println("[ERROR] failed to read bytes: ", err)
		}
		return randomBytes
	}

	result := make([]byte, n)
	bufferSize := int(float64(n) * 1.3)
	for i, j, randomBytes := 0, 0, []byte{}; i < n; j++ {
		if j%bufferSize == 0 {
			randomBytes = secureRandomBytes(bufferSize)
		}
		if idx := int(randomBytes[j%n] & letterIdxMask); idx < len(letterBytes) {
			result[i] = letterBytes[idx]
			i++
		}
	}

	return string(result)
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

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

const recursionPreventionHeader = "Caddy-Templates-Include"
