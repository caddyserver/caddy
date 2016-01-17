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
	if !strings.HasPrefix(host, "http") {
		host = "http://" + host
	}
	return staticProvider(host), nil
}

type NewFunc func(string) (Provider, error)

func Register(scheme string, initFunc NewFunc) {
	providers[scheme] = initFunc
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

// Config
type Config struct {
	Host string
	Err  error
}

// Watcher watches for changes in the store.
// Next blocks until a new host is available.
type Watcher interface {
	Next() <-chan Config
	Stop()
}

func init() {
	// register provider
	Register("http://", newStatic)
	Register("https://", newStatic)
	Register("", newStatic)
}
