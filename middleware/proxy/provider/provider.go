package provider

import (
	"errors"
	"fmt"
	"strings"
)

var (
	providers = make(map[string]NewFunc)

	ErrUnsupportedScheme = errors.New("scheme is not supported.")
)

type Provider interface {
	Hosts() ([]string, error)
}

type staticProvider string

func (s staticProvider) Hosts() ([]string, error) {
	return []string{string(s)}, nil
}

func newStatic(host string) (Provider, error) {
	return staticProvider(host), nil
}

// NewFunc creates a new Provider.
type NewFunc func(host string) (Provider, error)

func Register(scheme string, newFunc NewFunc) {
	providers[scheme] = newFunc
}

func Get(addr string) (Provider, error) {
	scheme := ""
	s := strings.SplitN(addr, "://", 2)
	if len(s) > 1 {
		scheme = s[0]
	}
	if f, ok := providers[scheme]; ok {
		return f(addr)
	}
	return nil, fmt.Errorf("%s %v", scheme, ErrUnsupportedScheme)
}

// DynamicProvider represents a dynamic hosts provider.
type DynamicProvider interface {
	Provider
	Watch() Watcher
}

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
