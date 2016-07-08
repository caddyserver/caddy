package rewrite

import (
	"net/http"
	"strconv"
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
		var status int
		var ext []string

		args := c.RemainingArgs()

		var matcher httpserver.RequestMatcher

		switch len(args) {
		case 1:
			base = args[0]
			fallthrough
		case 0:
			// Integrate request matcher for 'if' conditions.
			matcher, err = httpserver.SetupIfMatcher(c.Dispenser)
			if err != nil {
				return nil, err
			}
		block:
			for c.NextBlock() {
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
				case "ext":
					args1 := c.RemainingArgs()
					if len(args1) == 0 {
						return nil, c.ArgErr()
					}
					ext = args1
				case "status":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					status, _ = strconv.Atoi(c.Val())
					if status < 200 || (status > 299 && status < 400) || status > 499 {
						return nil, c.Err("status must be 2xx or 4xx")
					}
				default:
					if httpserver.IfMatcherKeyword(c.Val()) {
						continue block
					}
					return nil, c.ArgErr()
				}
			}
			// ensure to or status is specified
			if to == "" && status == 0 {
				return nil, c.ArgErr()
			}
			if rule, err = NewComplexRule(base, pattern, to, status, ext, matcher); err != nil {
				return nil, err
			}
			rules = append(rules, rule)

		// the only unhandled case is 2 and above
		default:
			rule = NewSimpleRule(args[0], strings.Join(args[1:], " "))
			rules = append(rules, rule)
		}

	}

	return rules, nil
}
