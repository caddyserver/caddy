// Package config contains utilities and types necessary for
// launching specially-configured server instances.
package config

import "os"

// Load loads a configuration file, parses it,
// and returns a slice of Config structs which
// can be used to create and configure server
// instances.
func Load(filename string) ([]Config, error) {
	p := parser{}
	err := p.lexer.Load(filename)
	if err != nil {
		return nil, err
	}
	defer p.lexer.Close()
	return p.Parse()
}

// IsNotFound returns whether or not the error is
// one which indicates that the configuration file
// was not found. (Useful for checking the error
// returned from Load).
func IsNotFound(err error) bool {
	return os.IsNotExist(err)
}

// Default makes a default configuration
// that's empty except for root, host, and port,
// which are essential for serving the cwd.
func Default() []Config {
	cfg := []Config{
		Config{
			Root: defaultRoot,
			Host: defaultHost,
			Port: defaultPort,
		},
	}
	return cfg
}

// config represents a server configuration. It
// is populated by parsing a config file. (Use
// the Load function.)
type Config struct {
	Host       string
	Port       string
	Root       string
	Gzip       bool
	RequestLog Log
	ErrorLog   Log
	Rewrites   []Rewrite
	Redirects  []Redirect
	Extensions []string
	ErrorPages map[int]string // Map of HTTP status code to filename
	Headers    []Headers
	TLS        TLSConfig
}

// Address returns the host:port of c as a string.
func (c Config) Address() string {
	return c.Host + ":" + c.Port
}

// Rewrite describes an internal location rewrite.
type Rewrite struct {
	From string
	To   string
}

// Redirect describes an HTTP redirect.
type Redirect struct {
	From string
	To   string
	Code int
}

// Log represents the settings for a log.
type Log struct {
	Enabled    bool
	OutputFile string
	Format     string
}

// Headers groups a slice of HTTP headers by a URL pattern.
type Headers struct {
	Url     string
	Headers []Header
}

// Header represents a single HTTP header, simply a name and value.
type Header struct {
	Name  string
	Value string
}

// TLSConfig describes how TLS should be configured and used,
// if at all. At least a certificate and key are required.
type TLSConfig struct {
	Enabled     bool
	Certificate string
	Key         string
}

// httpRedirs is a list of supported HTTP redirect codes.
var httpRedirs = map[string]int{
	"300": 300,
	"301": 301,
	"302": 302,
	"303": 303,
	"304": 304,
	"305": 305,
	"306": 306,
	"307": 307,
	"308": 308,
}

// httpErrors is a list of supported HTTP error codes.
var httpErrors = map[string]int{
	"400": 400,
	"401": 401,
	"402": 402,
	"403": 403,
	"404": 404,
	"405": 405,
	"406": 406,
	"407": 407,
	"408": 408,
	"409": 409,
	"410": 410,
	"411": 411,
	"412": 412,
	"413": 413,
	"414": 414,
	"415": 415,
	"416": 416,
	"417": 417,
	"418": 418,
	"419": 419,
	"420": 420,
	"422": 422,
	"423": 423,
	"424": 424,
	"426": 426,
	"428": 428,
	"429": 429,
	"431": 431,
	"440": 440,
	"444": 444,
	"449": 449,
	"450": 450,
	"451": 451,
	"494": 494,
	"495": 495,
	"496": 496,
	"497": 497,
	"498": 498,
	"499": 499,
	"500": 500,
	"501": 501,
	"502": 502,
	"503": 503,
	"504": 504,
	"505": 505,
	"506": 506,
	"507": 507,
	"508": 508,
	"509": 509,
	"510": 510,
	"511": 511,
	"520": 520,
	"521": 521,
	"522": 522,
	"523": 523,
	"524": 524,
	"598": 598,
	"599": 599,
}

const (
	defaultHost = "localhost"
	defaultPort = "8080"
	defaultRoot = "."
)

const (
	DefaultRequestsLog = "requests.log"
	DefaultErrorsLog   = "errors.log"
)
