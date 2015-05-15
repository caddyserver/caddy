package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/rewrite"
)

// Rewrite configures a new Rewrite middleware instance.
func Rewrite(c *Controller) (middleware.Middleware, error) {
	rewrites, err := rewriteParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return rewrite.Rewrite{Next: next, Rules: rewrites}
	}, nil
}

func rewriteParse(c *Controller) ([]rewrite.Rule, error) {
	var rewrites []rewrite.Rule
	var regexps []rewrite.Rule

	for c.Next() {
		var rule rewrite.Rule
		var err error

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			if args[0] != "regexp" {
				rule = rewrite.NewSimpleRule(args[0], args[1])
				rewrites = append(rewrites, rule)
				continue
			}

			var base = args[1]
			var pattern, to string
			var ext []string

			for c.NextBlock() {
				switch c.Val() {
				case "pattern":
					if !c.NextArg() {
						return rewrites, c.ArgErr()
					}
					pattern = c.Val()
				case "to":
					if !c.NextArg() {
						return rewrites, c.ArgErr()
					}
					to = c.Val()
				case "ext":
					args1 := c.RemainingArgs()
					if len(args1) == 0 {
						return rewrites, c.ArgErr()
					}
					ext = args1
				default:
					return rewrites, c.ArgErr()
				}
			}
			if pattern == "" || to == "" {
				return rewrites, c.ArgErr()
			}
			if rule, err = rewrite.NewRegexpRule(base, pattern, to, ext); err != nil {
				return rewrites, err
			}
			rewrites = append(regexps, rule)
		default:
			return rewrites, c.ArgErr()
		}

	}

	return append(rewrites, regexps...), nil
}
