//go:build !linux || nosystemd

package caddy

const globalReplacementProviders = []replacementProvider{
	defaultReplacementProvider{},
	fileReplacementProvider{},
}
