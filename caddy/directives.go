package caddy

import (
	"log"

	"github.com/mholt/caddy/caddy/https"
	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
)

var valid = struct{}{}

func init() {
	// The parse package must know which directives
	// are valid, but it must not import the setup
	// or config package. To solve this problem, we
	// fill up this map in our init function here.
	// The parse package does not need to know the
	// ordering of the directives.
	for _, dir := range directiveOrder {
		if dir.Setup != nil {
			parse.ValidDirectives[dir.Name] = valid
		}
	}
}

// Directives are registered in the order they should be
// executed. Middleware (directives that inject a handler)
// are executed in the order A-B-C-*-C-B-A, assuming
// they all call the Next handler in the chain.
//
// Ordering is VERY important. Every middleware will
// feel the effects of all other middleware below
// (after) them during a request, but they must not
// care what middleware above them are doing.
//
// For example, log needs to know the status code and
// exactly how many bytes were written to the client,
// which every other middleware can affect, so it gets
// registered first. The errors middleware does not
// care if gzip or log modifies its response, so it
// gets registered below them. Gzip, on the other hand,
// DOES care what errors does to the response since it
// must compress every output to the client, even error
// pages, so it must be registered before the errors
// middleware and any others that would write to the
// response.
//
// Middleware here with a nil setup func are "external" to caddy core, and must be activated.
var directiveOrder = []Directive{
	// Essential directives that initialize vital configuration settings
	{"root", setup.Root, "", ""},
	{"bind", setup.BindHost, "", ""},
	{"tls", https.Setup, "", ""},

	// Other directives that don't create HTTP handlers
	{"startup", setup.Startup, "", ""},
	{"shutdown", setup.Shutdown, "", ""},
	{"git", nil, "github.com/abiosoft/caddy-git", "Deploy your site with git push."},

	// Directives that inject handlers (middleware)
	{"log", setup.Log, "", ""},
	{"gzip", setup.Gzip, "", ""},
	{"errors", setup.Errors, "", ""},
	{"ipfilter", nil, "github.com/pyed/ipfilter", "Block or allow clients based on IP origin."},
	{"search", nil, "github.com/pedronasser/caddy-search", "Activates a site search engine"},
	{"header", setup.Headers, "", ""},
	{"cors", nil, "github.com/captncraig/cors/caddy", "Enable Cross Origin Resource Sharing"},
	{"rewrite", setup.Rewrite, "", ""},
	{"redir", setup.Redir, "", ""},
	{"ext", setup.Ext, "", ""},
	{"mime", setup.Mime, "", ""},
	{"basicauth", setup.BasicAuth, "", ""},
	{"jsonp", nil, "github.com/pschlump/caddy-jsonp", "Wrap regular JSON responses as JSONP"},
	{"internal", setup.Internal, "", ""},
	{"proxy", setup.Proxy, "", ""},
	{"fastcgi", setup.FastCGI, "", ""},
	{"websocket", setup.WebSocket, "", ""},
	{"markdown", setup.Markdown, "", ""},
	{"templates", setup.Templates, "", ""},
	{"browse", setup.Browse, "", ""},
	{"hugo", nil, "github.com/hacdias/caddy-hugo", "Powerful and easy static site generator with admin interface."},
}

// Directives returns the list of directives in order of priority.
func Directives() []string {
	directives := make([]string, len(directiveOrder))
	for i, d := range directiveOrder {
		directives[i] = d.name
	}
	return directives
}

// RegisterDirective adds the given directive to caddy's list of directives.
// Pass the name of a directive you want it to be placed after,
// otherwise it will be placed at the bottom of the stack.
func RegisterDirective(name string, setup SetupFunc, after string) {
	dir := Directive{Name: name, Setup: setup}
	idx := len(directiveOrder)
	for i := range directiveOrder {
		if directiveOrder[i].Name == after {
			idx = i + 1
			break
		}
	}
	newDirectives := append(directiveOrder[:idx], append([]Directive{dir}, directiveOrder[idx:]...)...)
	directiveOrder = newDirectives
	parse.ValidDirectives[name] = valid
}

// ActivateDirective provides a setup func for an external directive that we only have a placeholder for.
func ActivateDirective(name string, setup SetupFunc) {
	for i, d := range directiveOrder {
		if d.Name == name {
			if d.Setup != nil {
				log.Fatalf("Directive %s already activated", name)
			}
			d.Setup = setup
			directiveOrder[i] = d
			parse.ValidDirectives[name] = valid
			return
		}
	}
	log.Fatalf("Unknown directive %s", name)
}

// Directive ties together a directive name with its setup function.
type Directive struct {
	Name        string    `json:"directive"`
	Setup       SetupFunc `json:"-"`
	Package     string    `json:"package"`
	Description string    `json:"description"`
}

// GetDirectives returns a read-only copy of the current directive stack
func GetDirectives() []Directive {
	d := make([]Directive, len(directiveOrder))
	for i, dir := range directiveOrder {
		d[i] = dir
	}
	return d
}

// SetupFunc takes a controller and may optionally return a middleware.
// If the resulting middleware is not nil, it will be chained into
// the HTTP handlers in the order specified in this package.
type SetupFunc func(c *setup.Controller) (middleware.Middleware, error)
