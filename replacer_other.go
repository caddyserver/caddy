//go:build !linux || nosystemd

package caddy

var globalReplacementProviders = []replacementProvider{
	defaultReplacementProvider{},
	fileReplacementProvider{},
}
