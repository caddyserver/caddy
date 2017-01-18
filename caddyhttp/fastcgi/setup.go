package fastcgi

import (
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

	rules, err := fastcgiParse(c)
	if err != nil {
		return err
	}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Handler{
			Next:            next,
			Rules:           rules,
			Root:            cfg.Root,
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

	cfg := httpserver.GetConfig(c)
	absRoot, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}

	for c.Next() {
		args := c.RemainingArgs()

		if len(args) < 2 || len(args) > 3 {
			return rules, c.ArgErr()
		}

		rule := Rule{
			Root:        absRoot,
			Path:        args[0],
			ReadTimeout: 60 * time.Second,
			SendTimeout: 60 * time.Second,
		}
		upstreams := []string{args[1]}

		if len(args) == 3 {
			if err := fastcgiPreset(args[2], &rule); err != nil {
				return rules, err
			}
		}

		var err error
		var pool int
		var connectTimeout = 60 * time.Second
		var dialers []dialer
		var poolSize = -1

		for c.NextBlock() {
			switch c.Val() {
			case "root":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.Root = c.Val()

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

			case "upstream":
				args := c.RemainingArgs()

				if len(args) != 1 {
					return rules, c.ArgErr()
				}

				upstreams = append(upstreams, args[0])
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

			case "pool":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				pool, err = strconv.Atoi(c.Val())
				if err != nil {
					return rules, err
				}
				if pool >= 0 {
					poolSize = pool
				} else {
					return rules, c.Errf("positive integer expected, found %d", pool)
				}
			case "connect_timeout":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				connectTimeout, err = time.ParseDuration(c.Val())
				if err != nil {
					return rules, err
				}
			case "read_timeout":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				readTimeout, err := time.ParseDuration(c.Val())
				if err != nil {
					return rules, err
				}
				rule.ReadTimeout = readTimeout
			case "send_timeout":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				sendTimeout, err := time.ParseDuration(c.Val())
				if err != nil {
					return rules, err
				}
				rule.SendTimeout = sendTimeout
			}
		}

		for _, rawAddress := range upstreams {
			network, address := parseAddress(rawAddress)
			if poolSize >= 0 {
				dialers = append(dialers, &persistentDialer{
					size:    poolSize,
					network: network,
					address: address,
					timeout: connectTimeout,
				})
			} else {
				dialers = append(dialers, basicDialer{
					network: network,
					address: address,
					timeout: connectTimeout,
				})
			}
		}

		rule.dialer = &loadBalancingDialer{dialers: dialers}
		rule.Address = strings.Join(upstreams, ",")
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
