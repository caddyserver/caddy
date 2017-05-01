package rewrite

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("rewrite", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Rewrite middleware instance.
func setup(c *caddy.Controller) error {
	rewrites, err := rewriteParse(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Rewrite{
			Next:    next,
			FileSys: http.Dir(cfg.Root),
			Rules:   rewrites,
		}
	})

	return nil
}

func rewriteParse(c *caddy.Controller) ([]httpserver.HandlerConfig, error) {
	var rules []httpserver.HandlerConfig

	for c.Next() {
		var rule Rule
		var err error
		var base = "/"
		var pattern, to string
		var ext []string

		args := c.RemainingArgs()

		var matcher httpserver.RequestMatcher

		switch len(args) {
		case 1:
			base = args[0]
			fallthrough
		case 0:
			// Integrate request matcher for 'if' conditions.
			matcher, err = httpserver.SetupIfMatcher(c)
			if err != nil {
				return nil, err
			}

			for c.NextBlock() {
				if httpserver.IfMatcherKeyword(c) {
					continue
				}
				switch c.Val() {
				case "r", "regexp":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					pattern = c.Val()
				case "to":
					args1 := c.RemainingArgs()
					if len(args1) == 0 {
						return nil, c.ArgErr()
					}
					to = strings.Join(args1, " ")
					// ensure rewrite path begins with /
					if !strings.HasPrefix(to, "/") {
						return nil, c.Errf("%s:%d - Syntax error: Rewrite path must begin with '/'. Provided: '%s'", c.File(), c.Line(), c.Val())
					}
				case "ext":
					args1 := c.RemainingArgs()
					if len(args1) == 0 {
						return nil, c.ArgErr()
					}
					ext = args1
				default:
					return nil, c.ArgErr()
				}
			}
			// ensure to is specified
			if to == "" {
				return nil, c.ArgErr()
			}

			if rule, err = NewComplexRule(base, pattern, to, ext, matcher); err != nil {
				return nil, err
			}
			rules = append(rules, rule)

		// handle case of 2 arguments: "from to"
		default:
			// ensure rewrite path begins with /
			topath := strings.Join(args[1:], " ")
			if !strings.HasPrefix(topath, "/") {
				return nil, c.Errf("%s:%d - Syntax error: Rewrite path must begin with '/'. Provided: '%s'", c.File(), c.Line(), c.Val())
			}
			rule = NewSimpleRule(args[0], topath)
			rules = append(rules, rule)
		}

	}

	return rules, nil
}
