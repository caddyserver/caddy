package digestauth

import (
	"strings"
	//"syscall"
	"path/filepath"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("digestauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new DigestAuth middleware instance.
func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	root := cfg.Root

	rules, err := digestAuthParse(c)
	if err != nil {
		return err
	}

	digest := DigestAuth{Rules: rules}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		digest.Next = next
		digest.SiteRoot = root
		return digest
	})

	return nil
}

func digestAuthParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule
	cfg := httpserver.GetConfig(c)

	var err error
	for c.Next() {
		var rule Rule

		args := c.RemainingArgs()
		username := ""
		password := ""

		switch len(args) {
		case 2:
			username = args[0]
			password = args[1]
		case 3:
			rule.Resources = append(rule.Resources, args[0])
			username = args[1]
			password = args[2]
		default:
			return rules, c.ArgErr()
		}

		// If nested block is present, process it here
		for c.NextBlock() {
			val := c.Val()
			args = c.RemainingArgs()
			switch len(args) {
			case 0:
				// Assume single argument is path resource
				rule.Resources = append(rule.Resources, val)
			case 1:
				if val == "realm" {
					if rule.Realm == "" {
						rule.Realm = strings.Replace(args[0], `"`, `\"`, -1)
					} else {
						return rules, c.Errf("\"realm\" subdirective can only be specified once")
					}
				} else {
					return rules, c.Errf("expecting \"realm\", got \"%s\"", val)
				}
			default:
				return rules, c.ArgErr()
			}
		}

		err = nil

		if username == "" {
			return rules, c.Errf("Username can't be empty")
		} else if password == "" {
			return rules, c.Errf("Password can't be empty")
		} else if strings.HasPrefix(password, "htdigest=") {
			rule.Users, err = NewHtdigestUserStore(filepath.Join(cfg.Root, password[9:]), nil)
		} else {
			rule.Users, err = NewSimpleUserStore(map[string]string{username: password}), nil
		}

		if err != nil {
			return rules, c.Errf("Get password storage: %v", err)
		}

		if rule.Realm == "" {
			rule.Realm = "Restricted"
		}

		rule.Digester = NewDigestHandler(rule.Realm, nil, nil, rule.Users)
		rules = append(rules, rule)
	}

	return rules, nil
}
