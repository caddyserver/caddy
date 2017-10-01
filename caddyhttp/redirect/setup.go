// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redirect

import (
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("redir", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Redirect middleware instance.
func setup(c *caddy.Controller) error {
	rules, err := redirParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Redirect{Next: next, Rules: rules}
	})

	return nil
}

func redirParse(c *caddy.Controller) ([]Rule, error) {
	var redirects []Rule

	cfg := httpserver.GetConfig(c)

	initRule := func(rule *Rule, defaultCode string, args []string) error {
		rule.FromScheme = func() string {
			if cfg.TLS.Enabled {
				return "https"
			}
			return "http"
		}

		var (
			from = "/"
			to   string
			code = defaultCode
		)
		switch len(args) {
		case 1:
			// To specified (catch-all redirect)
			// Not sure why user is doing this in a table, as it causes all other redirects to be ignored.
			// As such, this feature remains undocumented.
			to = args[0]
		case 2:
			// From and To specified
			from = args[0]
			to = args[1]
		case 3:
			// From, To, and Code specified
			from = args[0]
			to = args[1]
			code = args[2]
		default:
			return c.ArgErr()
		}

		rule.FromPath = from
		rule.To = to
		if code == "meta" {
			rule.Meta = true
			code = defaultCode
		}
		if codeNumber, ok := httpRedirs[code]; ok {
			rule.Code = codeNumber
		} else {
			return c.Errf("Invalid redirect code '%v'", code)
		}

		return nil
	}

	// checkAndSaveRule checks the rule for validity (except the redir code)
	// and saves it if it's valid, or returns an error.
	checkAndSaveRule := func(rule Rule) error {
		if rule.FromPath == rule.To {
			return c.Err("'from' and 'to' values of redirect rule cannot be the same")
		}

		// prevent obvious duplicates (rules with if statements exempt)
		if ifm, ok := rule.RequestMatcher.(httpserver.IfMatcher); !ok || !ifm.Enabled {
			for _, otherRule := range redirects {
				if otherRule.FromPath == rule.FromPath {
					return c.Errf("rule with duplicate 'from' value: %s -> %s", otherRule.FromPath, otherRule.To)
				}
			}
		}

		redirects = append(redirects, rule)
		return nil
	}

	const initDefaultCode = "301"

	for c.Next() {
		args := c.RemainingArgs()
		matcher, err := httpserver.SetupIfMatcher(c)
		if err != nil {
			return nil, err
		}

		var hadOptionalBlock bool
		for c.NextBlock() {
			if httpserver.IfMatcherKeyword(c) {
				continue
			}

			hadOptionalBlock = true

			rule := Rule{
				RequestMatcher: matcher,
			}

			defaultCode := initDefaultCode
			// Set initial redirect code
			if len(args) == 1 {
				defaultCode = args[0]
			}

			// RemainingArgs only gets the values after the current token, but in our
			// case we want to include the current token to get an accurate count.
			insideArgs := append([]string{c.Val()}, c.RemainingArgs()...)
			err := initRule(&rule, defaultCode, insideArgs)
			if err != nil {
				return redirects, err
			}

			err = checkAndSaveRule(rule)
			if err != nil {
				return redirects, err
			}
		}

		if !hadOptionalBlock {
			rule := Rule{
				RequestMatcher: matcher,
			}
			err := initRule(&rule, initDefaultCode, args)
			if err != nil {
				return redirects, err
			}

			err = checkAndSaveRule(rule)
			if err != nil {
				return redirects, err
			}
		}
	}

	return redirects, nil
}

// httpRedirs is a list of supported HTTP redirect codes.
var httpRedirs = map[string]int{
	"300": http.StatusMultipleChoices,
	"301": http.StatusMovedPermanently,
	"302": http.StatusFound, // (NOT CORRECT for "Temporary Redirect", see 307)
	"303": http.StatusSeeOther,
	"304": http.StatusNotModified,
	"305": http.StatusUseProxy,
	"307": http.StatusTemporaryRedirect,
	"308": http.StatusPermanentRedirect, // Permanent Redirect (RFC 7238)
}
