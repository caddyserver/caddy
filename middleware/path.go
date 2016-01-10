package middleware

import "strings"

// Path represents a URI path, maybe with pattern characters.
type Path string

// Matches checks to see if other matches p.
//
// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily and consistently matched.
func (p Path) Matches(other string) bool {
	return strings.HasPrefix(string(p), other)
}

// ConfigPath represents a configuration base path.
type ConfigPath interface {
	// Path returns base path value.
	Path() string
}

// ConfigPaths is a list of ConfigPath
type ConfigPaths []ConfigPath

// Add adds a new ConfigPath to the list in descending order of
// path length.
func (paths *ConfigPaths) Add(b ConfigPath) {
	idx := len(*paths)
	for i, p := range *paths {
		if len(p.Path()) < len(b.Path()) {
			idx = i
			break
		}
	}
	part := []ConfigPath{b}
	if idx < len(*paths) {
		part = append(part, (*paths)[idx:]...)
	}
	*paths = append((*paths)[:idx], part...)
}

// Each iterates through all config paths and calls f on each iteration
func (paths ConfigPaths) Each(f func(ConfigPath)) {
	for _, p := range paths {
		f(p)
	}
}
