package fastcgi

import (
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("fastcgi", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new FastCGI middleware instance.
func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	absRoot, err := filepath.Abs(cfg.Root)
	if err != nil {
		return err
	}

	rules, err := fastcgiParse(c)
	if err != nil {
		return err
	}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Handler{
			Next:            next,
			Rules:           rules,
			Root:            cfg.Root,
			AbsRoot:         absRoot,
			FileSys:         http.Dir(cfg.Root),
			SoftwareName:    caddy.AppName,
			SoftwareVersion: caddy.AppVersion,
			ServerName:      cfg.Addr.Host,
			ServerPort:      cfg.Addr.Port,
		}
	})

	return nil
}

func fastcgiParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule

		args := c.RemainingArgs()

		if !(len(args) > 1) {
			return rules, c.ArgErr()
		}

		rule.Path = args[0]
		lastIndex := len(args)

		var addresses = args[1:lastIndex]
		var dialers []dialer
		var pooled bool

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
				args := c.RemainingArgs()
				if len(args) == 0 {
					return rules, c.ArgErr()
				}
				rule.IndexFiles = args
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

			case "preset":
				presetArgs := c.RemainingArgs()

				if len(presetArgs) < 2 {
					return rules, c.ArgErr()
				}

				if err := fastcgiPreset(presetArgs[0], &rule); err != nil {
					return rules, err
				}

			case "pool":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				pool, err := strconv.Atoi(c.Val())
				if err != nil {
					return rules, err
				}
				if pool >= 0 {
					pooled = true
					for _, rawAddress := range addresses {
						network, address := parseAddress(rawAddress)
						dialers = append(dialers, &persistentDialer{size: pool, network: network, address: address})
					}
				} else {
					return rules, c.Errf("positive integer expected, found %d", pool)
				}
			}
		}

		if !pooled {
			for _, rawAddress := range addresses {
				network, address := parseAddress(rawAddress)
				dialers = append(dialers, basicDialer{network: network, address: address})
			}
		}

		rule.dialer = &loadBalancingDialer{dialers: dialers}
		rule.Address = strings.Join(addresses, ",")
		rules = append(rules, rule)
	}

	return rules, nil
}

// fastcgiPreset configures rule according to name. It returns an error if
// name is not a recognized preset name.
func fastcgiPreset(name string, rule *Rule) error {
	switch name {
	case "php":
		rule.Ext = ".php"
		rule.SplitPath = ".php"
		rule.IndexFiles = []string{"index.php"}
	default:
		return errors.New(name + " is not a valid preset name")
	}
	return nil
}
