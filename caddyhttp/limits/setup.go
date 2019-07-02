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

package limits

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

const (
	serverType = "http"
	pluginName = "limits"
)

func init() {
	caddy.RegisterPlugin(pluginName, caddy.Plugin{
		ServerType: serverType,
		Action:     setupLimits,
	})
}

// pathLimitUnparsed is a PathLimit before it's parsed
type pathLimitUnparsed struct {
	Path  string
	Limit string
}

func setupLimits(c *caddy.Controller) error {
	bls, err := parseLimits(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Limit{Next: next, BodyLimits: bls}
	})
	return nil
}

func parseLimits(c *caddy.Controller) ([]httpserver.PathLimit, error) {
	config := httpserver.GetConfig(c)

	if !c.Next() {
		return nil, c.ArgErr()
	}

	args := c.RemainingArgs()
	argList := []pathLimitUnparsed{}
	headerLimit := ""

	switch len(args) {
	case 0:
		// Format: limits {
		//	header <limit>
		//	body <path> <limit>
		//	body <limit>
		//	...
		// }
		for c.NextBlock() {
			kind := c.Val()
			pathOrLimit := c.RemainingArgs()
			switch kind {
			case "header":
				if len(pathOrLimit) != 1 {
					return nil, c.ArgErr()
				}
				headerLimit = pathOrLimit[0]
			case "body":
				if len(pathOrLimit) == 1 {
					argList = append(argList, pathLimitUnparsed{
						Path:  "/",
						Limit: pathOrLimit[0],
					})
					break
				}

				if len(pathOrLimit) == 2 {
					argList = append(argList, pathLimitUnparsed{
						Path:  pathOrLimit[0],
						Limit: pathOrLimit[1],
					})
					break
				}

				fallthrough
			default:
				return nil, c.ArgErr()
			}
		}
	case 1:
		// Format: limits <limit>
		headerLimit = args[0]
		argList = []pathLimitUnparsed{{
			Path:  "/",
			Limit: args[0],
		}}
	default:
		return nil, c.ArgErr()
	}

	if headerLimit != "" {
		size := parseSize(headerLimit)
		if size < 1 { // also disallow size = 0
			return nil, c.ArgErr()
		}
		config.Limits.MaxRequestHeaderSize = size
	}

	if len(argList) > 0 {
		pathLimit, err := parseArguments(argList)
		if err != nil {
			return nil, c.ArgErr()
		}
		SortPathLimits(pathLimit)
		config.Limits.MaxRequestBodySizes = pathLimit
	}

	return config.Limits.MaxRequestBodySizes, nil
}

func parseArguments(args []pathLimitUnparsed) ([]httpserver.PathLimit, error) {
	pathLimit := []httpserver.PathLimit{}

	for _, pair := range args {
		size := parseSize(pair.Limit)
		if size < 1 { // also disallow size = 0
			return pathLimit, errors.New("Parse failed")
		}
		pathLimit = addPathLimit(pathLimit, pair.Path, size)
	}
	return pathLimit, nil
}

var validUnits = []struct {
	symbol     string
	multiplier int64
}{
	{"KB", 1024},
	{"MB", 1024 * 1024},
	{"GB", 1024 * 1024 * 1024},
	{"B", 1},
	{"", 1}, // defaulting to "B"
}

// parseSize parses the given string as size limit
// Size are positive numbers followed by a unit (case insensitive)
// Allowed units: "B" (bytes), "KB" (kilo), "MB" (mega), "GB" (giga)
// If the unit is omitted, "b" is assumed
// Returns the parsed size in bytes, or -1 if cannot parse
func parseSize(sizeStr string) int64 {
	sizeStr = strings.ToUpper(sizeStr)

	for _, unit := range validUnits {
		if strings.HasSuffix(sizeStr, unit.symbol) {
			size, err := strconv.ParseInt(sizeStr[0:len(sizeStr)-len(unit.symbol)], 10, 64)
			if err != nil {
				return -1
			}
			return size * unit.multiplier
		}
	}

	// Unreachable code
	return -1
}

// addPathLimit appends the path-to-request body limit mapping to pathLimit
// Slashes are checked and added to path if necessary. Duplicates are ignored.
func addPathLimit(pathLimit []httpserver.PathLimit, path string, limit int64) []httpserver.PathLimit {
	// Enforces preceding slash
	if path[0] != '/' {
		path = "/" + path
	}

	// Use the last value if there are duplicates
	for i, p := range pathLimit {
		if p.Path == path {
			pathLimit[i].Limit = limit
			return pathLimit
		}
	}

	return append(pathLimit, httpserver.PathLimit{Path: path, Limit: limit})
}

// SortPathLimits sort pathLimits by their paths length, longest first
func SortPathLimits(pathLimits []httpserver.PathLimit) {
	sorter := &pathLimitSorter{
		pathLimits: pathLimits,
		by:         LengthDescending,
	}
	sort.Sort(sorter)
}

// structs and methods implementing the sorting interfaces for PathLimit
type pathLimitSorter struct {
	pathLimits []httpserver.PathLimit
	by         func(p1, p2 *httpserver.PathLimit) bool
}

func (s *pathLimitSorter) Len() int {
	return len(s.pathLimits)
}

func (s *pathLimitSorter) Swap(i, j int) {
	s.pathLimits[i], s.pathLimits[j] = s.pathLimits[j], s.pathLimits[i]
}

func (s *pathLimitSorter) Less(i, j int) bool {
	return s.by(&s.pathLimits[i], &s.pathLimits[j])
}

// LengthDescending is the comparator for SortPathLimits
func LengthDescending(p1, p2 *httpserver.PathLimit) bool {
	return len(p1.Path) > len(p2.Path)
}
