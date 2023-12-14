// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyfile

import (
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// parseVariadic determines if the token is a variadic placeholder,
// and if so, determines the index range (start/end) of args to use.
// Returns a boolean signaling whether a variadic placeholder was found,
// and the start and end indices.
func parseVariadic(token Token, argCount int) (bool, int, int) {
	if !strings.HasPrefix(token.Text, "{args[") {
		return false, 0, 0
	}
	if !strings.HasSuffix(token.Text, "]}") {
		return false, 0, 0
	}

	argRange := strings.TrimSuffix(strings.TrimPrefix(token.Text, "{args["), "]}")
	if argRange == "" {
		caddy.Log().Named("caddyfile").Warn(
			"Placeholder "+token.Text+" cannot have an empty index",
			zap.String("file", token.File+":"+strconv.Itoa(token.Line)), zap.Strings("import_chain", token.imports))
		return false, 0, 0
	}

	start, end, found := strings.Cut(argRange, ":")

	// If no ":" delimiter is found, this is not a variadic.
	// The replacer will pick this up.
	if !found {
		return false, 0, 0
	}

	// A valid token may contain several placeholders, and
	// they may be separated by ":". It's not variadic.
	// https://github.com/caddyserver/caddy/issues/5716
	if strings.Contains(start, "}") || strings.Contains(end, "{") {
		return false, 0, 0
	}

	var (
		startIndex = 0
		endIndex   = argCount
		err        error
	)
	if start != "" {
		startIndex, err = strconv.Atoi(start)
		if err != nil {
			caddy.Log().Named("caddyfile").Warn(
				"Variadic placeholder "+token.Text+" has an invalid start index",
				zap.String("file", token.File+":"+strconv.Itoa(token.Line)), zap.Strings("import_chain", token.imports))
			return false, 0, 0
		}
	}
	if end != "" {
		endIndex, err = strconv.Atoi(end)
		if err != nil {
			caddy.Log().Named("caddyfile").Warn(
				"Variadic placeholder "+token.Text+" has an invalid end index",
				zap.String("file", token.File+":"+strconv.Itoa(token.Line)), zap.Strings("import_chain", token.imports))
			return false, 0, 0
		}
	}

	// bound check
	if startIndex < 0 || startIndex > endIndex || endIndex > argCount {
		caddy.Log().Named("caddyfile").Warn(
			"Variadic placeholder "+token.Text+" indices are out of bounds, only "+strconv.Itoa(argCount)+" argument(s) exist",
			zap.String("file", token.File+":"+strconv.Itoa(token.Line)), zap.Strings("import_chain", token.imports))
		return false, 0, 0
	}
	return true, startIndex, endIndex
}

// makeArgsReplacer prepares a Replacer which can replace
// non-variadic args placeholders in imported tokens.
func makeArgsReplacer(args []string) *caddy.Replacer {
	repl := caddy.NewEmptyReplacer()
	repl.Map(func(key string) (any, bool) {
		// TODO: Remove the deprecated {args.*} placeholder
		// support at some point in the future
		if matches := argsRegexpIndexDeprecated.FindStringSubmatch(key); len(matches) > 0 {
			// What's matched may be a substring of the key
			if matches[0] != key {
				return nil, false
			}

			value, err := strconv.Atoi(matches[1])
			if err != nil {
				caddy.Log().Named("caddyfile").Warn(
					"Placeholder {args." + matches[1] + "} has an invalid index")
				return nil, false
			}
			if value >= len(args) {
				caddy.Log().Named("caddyfile").Warn(
					"Placeholder {args." + matches[1] + "} index is out of bounds, only " + strconv.Itoa(len(args)) + " argument(s) exist")
				return nil, false
			}
			caddy.Log().Named("caddyfile").Warn(
				"Placeholder {args." + matches[1] + "} deprecated, use {args[" + matches[1] + "]} instead")
			return args[value], true
		}

		// Handle args[*] form
		if matches := argsRegexpIndex.FindStringSubmatch(key); len(matches) > 0 {
			// What's matched may be a substring of the key
			if matches[0] != key {
				return nil, false
			}

			if strings.Contains(matches[1], ":") {
				caddy.Log().Named("caddyfile").Warn(
					"Variadic placeholder {args[" + matches[1] + "]} must be a token on its own")
				return nil, false
			}
			value, err := strconv.Atoi(matches[1])
			if err != nil {
				caddy.Log().Named("caddyfile").Warn(
					"Placeholder {args[" + matches[1] + "]} has an invalid index")
				return nil, false
			}
			if value >= len(args) {
				caddy.Log().Named("caddyfile").Warn(
					"Placeholder {args[" + matches[1] + "]} index is out of bounds, only " + strconv.Itoa(len(args)) + " argument(s) exist")
				return nil, false
			}
			return args[value], true
		}

		// Not an args placeholder, ignore
		return nil, false
	})
	return repl
}

var (
	argsRegexpIndexDeprecated = regexp.MustCompile(`args\.(.+)`)
	argsRegexpIndex           = regexp.MustCompile(`args\[(.+)]`)
)
