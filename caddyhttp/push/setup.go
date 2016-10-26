package push

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("push", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// ErrNotSupported is returned when push directive is not available
var ErrNotSupported = errors.New("push directive is available when build on golang 1.8")

var errInvalidFormat = errors.New("invalid format, expected push path [resources, ]")
var errInvalidHeader = errors.New("header directive requires [name] [value]")

var errHeaderStartsWithColon = errors.New("header cannot start with colon")
var errMethodNotSupported = errors.New("push supports only GET and HEAD methods")

// setup configures a new Push middleware
func setup(c *caddy.Controller) error {

	if !http2PushSupported() {
		return ErrNotSupported
	}

	rules, err := parsePushRules(c)

	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Middleware{Next: next, Rules: rules}
	})

	return nil
}

func parsePushRules(c *caddy.Controller) ([]Rule, error) {
	var rules = make(map[string]*Rule)
	var emptyRules = []Rule{}

	for c.NextLine() {
		if !c.NextArg() {
			return emptyRules, c.ArgErr()
		}

		path := c.Val()
		args := c.RemainingArgs()

		if len(args) < 1 {
			return emptyRules, errInvalidFormat
		}

		var rule *Rule

		if existingRule, ok := rules[path]; ok {
			rule = existingRule
		} else {
			rule = new(Rule)
			rule.Path = path
			rules[rule.Path] = rule
		}

		var resources []Resource

		for i := 0; i < len(args); i++ {
			resources = append(resources, Resource{
				Path:   args[i],
				Method: http.MethodGet,
				Header: http.Header{},
			})
		}

		for c.NextBlock() {
			switch c.Val() {
			case "method":
				if !c.NextArg() {
					return emptyRules, c.ArgErr()
				}

				method := c.Val()

				if err := validateMethod(method); err != nil {
					return emptyRules, errMethodNotSupported
				}

				for index := range resources {
					resources[index].Method = method
				}

			case "header":
				args := c.RemainingArgs()

				if len(args) != 2 {
					return emptyRules, errInvalidHeader
				}

				if err := validateHeader(args[0]); err != nil {
					return emptyRules, err
				}

				for index := range resources {
					resources[index].Header.Add(args[0], args[1])
				}
			}
		}

		rule.Resources = append(rule.Resources, resources...)
	}

	var returnRules []Rule

	for _, rule := range rules {
		returnRules = append(returnRules, *rule)
	}

	return returnRules, nil
}

// rules based on https://go-review.googlesource.com/#/c/29439/4/http2/go18.go#75
func validateHeader(header string) error {
	if strings.HasPrefix(header, ":") {
		return errHeaderStartsWithColon
	}

	switch strings.ToLower(header) {
	case "content-length", "content-encoding", "trailer", "te", "expect", "host":
		return fmt.Errorf("push headers cannot include %s", header)
	}

	return nil
}

// rules based on https://go-review.googlesource.com/#/c/29439/4/http2/go18.go#94
func validateMethod(method string) error {
	if method != http.MethodGet && method != http.MethodHead {
		return errMethodNotSupported
	}

	return nil
}
