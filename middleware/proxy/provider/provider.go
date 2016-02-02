package provider

import (
	"errors"
	"fmt"
	"strings"
)

var (
	providers = make(map[string]NewProviderFunc)

	errUnsupportedScheme = errors.New("scheme is not supported.")
)

// Provider is hosts provider.
type Provider interface {
	// Hosts returns all hosts provided by this provider.
	Hosts() ([]string, error)
}

// NewProviderFunc creates a new Provider.
type NewProviderFunc func(host string) (Provider, error)

// Register registers a url scheme against a new provider function.
func Register(scheme string, newFunc NewProviderFunc) {
	providers[scheme] = newFunc
}

// Get fetches a provider using the scheme of the provided address.
func Get(addr string) (Provider, error) {
	scheme := ""
	s := strings.SplitN(addr, "://", 2)
	if len(s) > 1 {
		scheme = s[0]
	}
	if f, ok := providers[scheme]; ok {
		return f(addr)
	}
	return nil, fmt.Errorf("%s %v", scheme, errUnsupportedScheme)
}
