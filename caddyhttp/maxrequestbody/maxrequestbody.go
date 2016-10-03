package maxrequestbody

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

const (
	serverType = "http"
	pluginName = "maxrequestbody"
)

func init() {
	caddy.RegisterPlugin(pluginName, caddy.Plugin{
		ServerType: serverType,
		Action:     setupMaxRequestBody,
	})
}

func setupMaxRequestBody(c *caddy.Controller) error {
	config := httpserver.GetConfig(c)

	if !c.Next() {
		return c.ArgErr()
	}

	args := c.RemainingArgs()
	pathLimit, err := parseArguments(args)
	if err != nil {
		return c.ArgErr()
	}

	SortPathLimits(pathLimit)

	config.MaxRequestBodySizes = pathLimit

	return nil
}

func parseArguments(args []string) ([]httpserver.PathLimit, error) {
	pathLimit := []httpserver.PathLimit{}
	// Arguments appear in pairs of "<path> <limit>"
	// If there's an argument that's not paired, it's assumed to be
	// the limit used for all remaining paths ("/")
	if len(args)%2 == 1 {
		args = append([]string{"/"}, args...)
	}

	i := 0
	for i < len(args) {
		path := args[i]
		limitStr := args[i+1]
		i = i + 2

		size := parseSize(limitStr)
		if size < 1 { // also disallow size = 0
			return pathLimit, errors.New("Parse failed")
		}
		pathLimit = addPathLimit(pathLimit, path, size)
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
