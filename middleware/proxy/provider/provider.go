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

// staticProvider cater for static hardcoded hosts.
type staticProvider string

// Hosts satisfies Provider interface.
func (s staticProvider) Hosts() ([]string, error) {
	return []string{string(s)}, nil
}

// newStatic creates a new static host provider.
func newStatic(host string) (Provider, error) {
	return staticProvider(host), nil
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

// DynamicProvider represents a dynamic hosts provider.
type DynamicProvider interface {
	Provider
	// Watch creates a new Watcher.
	Watch() Watcher
}

// WatcherMsg is the message sent by Watcher when there is a
// change to a host.
type WatcherMsg struct {
	// Host is the affected host
	Host string
	// Remove is true if the host should be removed instead.
	Remove bool
}

// Watcher watches for changes in the store.
// Next blocks until a new host is available.
type Watcher interface {
	Next() (msg WatcherMsg, err error)
}

func init() {
	// register static provider
	Register("http", newStatic)
	Register("https", newStatic)
	Register("", newStatic)
}
