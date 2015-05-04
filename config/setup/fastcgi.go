package setup

import (
	"errors"
	"path/filepath"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/fastcgi"
)

// FastCGI configures a new FastCGI middleware instance.
func FastCGI(c *Controller) (middleware.Middleware, error) {
	root, err := filepath.Abs(c.Root)
	if err != nil {
		return nil, err
	}

	rules, err := fastcgiParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return fastcgi.Handler{
			Next:            next,
			Rules:           rules,
			Root:            root,
			SoftwareName:    "Caddy", // TODO: Once generators are not in the same pkg as handler, obtain this from some global const
			SoftwareVersion: "",      // TODO: Get this from some global const too
			// TODO: Set ServerName and ServerPort to correct values... (as user defined in config)
		}
	}, nil
}

func fastcgiParse(c *Controller) ([]fastcgi.Rule, error) {
	var rules []fastcgi.Rule

	for c.Next() {
		var rule fastcgi.Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 0:
			return rules, c.ArgErr()
		case 1:
			rule.Path = "/"
			rule.Address = args[0]
		case 2:
			rule.Path = args[0]
			rule.Address = args[1]
		case 3:
			rule.Path = args[0]
			rule.Address = args[1]
			err := fastcgiPreset(args[2], &rule)
			if err != nil {
				return rules, c.Err("Invalid fastcgi rule preset '" + args[2] + "'")
			}
		}

		for c.NextBlock() {
			switch c.Val() {
			case "ext":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.Ext = c.Val()
			case "split":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.SplitPath = c.Val()
			case "index":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.IndexFile = c.Val()
			case "env":
				envArgs := c.RemainingArgs()
				if len(envArgs) < 2 {
					return rules, c.ArgErr()
				}
				rule.EnvVars = append(rule.EnvVars, [2]string{envArgs[0], envArgs[1]})
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// fastcgiPreset configures rule according to name. It returns an error if
// name is not a recognized preset name.
func fastcgiPreset(name string, rule *fastcgi.Rule) error {
	switch name {
	case "php":
		rule.Ext = ".php"
		rule.SplitPath = ".php"
		rule.IndexFile = "index.php"
	default:
		return errors.New(name + " is not a valid preset name")
	}
	return nil
}
