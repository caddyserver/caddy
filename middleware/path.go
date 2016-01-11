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

// Config represents a configuration.
type Config interface {
	// Path returns base path value.
	Path() string
}

// Configs is a list of Config
type Configs []Config

// Add adds a new Config to the list in descending order of
// path length.
func (configs *Configs) Add(c Config) {
	idx := len(*configs)
	for i, config := range *configs {
		if len(config.Path()) < len(c.Path()) {
			idx = i
			break
		}
	}
	part := []Config{c}
	if idx < len(*configs) {
		part = append(part, (*configs)[idx:]...)
	}
	*configs = append((*configs)[:idx], part...)
}

// Each iterates through all configs and calls f on each iteration
func (configs Configs) Each(f func(Config)) {
	for _, c := range configs {
		f(c)
	}
}
