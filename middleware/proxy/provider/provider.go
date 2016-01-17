package provider

import "github.com/mholt/caddy/middleware/proxy/provider/etcd"

type Provider interface {
	Hosts() ([]string, error)
}

type staticProvider string

func (s staticProvider) Hosts([]string, error) {
	return []string{s}, nil
}

func newStaticProvider(host string) (Provider, error) {
	return staticProvider(host)
}

var providers = make(map[string]NewFunc)

type NewFunc func(string) (Provider, error)

func RegisterProvider(scheme string, initFunc NewFunc) {
	providers[scheme] = initFunc
}

// DynamicProvider represents a dynamic hosts provider.
type DynamicProvider interface {
	Provider
	Watch() Watcher
}

// Watcher watches for changes in the store.
// Next blocks until a new host is available.
type Watcher interface {
	Next() (host string, err error)
}

func init() {
	// register all providers
	RegisterProvider("http://", newStaticProvider)
	RegisterProvider("https://", newStaticProvider)
	RegisterProvider("etcd://", etcd.New)
}
