package setup

import (
	"net/http"
	"path/filepath"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/scgi"
)

// SCGI configures a new SCGI middleware instance.
func SCGI(c *Controller) (middleware.Middleware, error) {
	absRoot, err := filepath.Abs(c.Root)
	if err != nil {
		return nil, err
	}

	rules, err := scgiParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return scgi.Handler{
			Next:            next,
			Rules:           rules,
			Root:            c.Root,
			AbsRoot:         absRoot,
			FileSys:         http.Dir(c.Root),
			SoftwareName:    c.AppName,
			SoftwareVersion: c.AppVersion,
			ServerName:      c.Host,
			ServerPort:      c.Port,
		}
	}, nil
}

func scgiParse(c *Controller) ([]scgi.Rule, error) {
	var rules []scgi.Rule

	for c.Next() {
		var rule scgi.Rule

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
		}

		for c.NextBlock() {
			switch c.Val() {
			case "env":
				envArgs := c.RemainingArgs()
				if len(envArgs) < 2 {
					return rules, c.ArgErr()
				}
				rule.EnvVars = append(rule.EnvVars, [2]string{envArgs[0], envArgs[1]})
			case "except":
				ignoredPaths := c.RemainingArgs()
				if len(ignoredPaths) == 0 {
					return rules, c.ArgErr()
				}
				rule.IgnoredSubPaths = ignoredPaths
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
