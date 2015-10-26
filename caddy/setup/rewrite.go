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
	var simpleRules []rewrite.Rule
	var regexpRules []rewrite.Rule

	for c.Next() {
		var rule rewrite.Rule
		var err error
		var base = "/"
		var pattern, to string
		var ext []string

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			rule = rewrite.NewSimpleRule(args[0], args[1])
			simpleRules = append(simpleRules, rule)
		case 1:
			base = args[0]
			fallthrough
		case 0:
			for c.NextBlock() {
				switch c.Val() {
				case "r", "regexp":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					pattern = c.Val()
				case "to":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					to = c.Val()
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
			// ensure pattern and to are specified
			if pattern == "" || to == "" {
				return nil, c.ArgErr()
			}
			if rule, err = rewrite.NewRegexpRule(base, pattern, to, ext); err != nil {
				return nil, err
			}
			regexpRules = append(regexpRules, rule)
		default:
			return nil, c.ArgErr()
		}

	}

	// put simple rules in front to avoid regexp computation for them
	return append(simpleRules, regexpRules...), nil
}
