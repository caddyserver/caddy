// Package etcd is an Etcd backed provider.
package etcd

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/etcd/client"
	"github.com/mholt/caddy/middleware/proxy/provider"
	"golang.org/x/net/context"
)

const (
	// Scheme is Ectd url scheme.
	Scheme = "etcd"

	// DefaultDirectory is the default Etcd config directory.
	DefaultDirectory = "/caddyserver.com/proxy/default/hosts/"
)

var (
	errInvalidScheme  = errors.New("invalid Etcd scheme")
	errNotDirectory   = errors.New("not an Etcd directory")
	errNotKey         = errors.New("not an Etcd key")
	errNotInDirectory = errors.New("not in expected directory")
)

// Provider is Etcd provider.
type Provider struct {
	endpoints []string
	directory string
	username  string
	password  string
	client.KeysAPI
}

// New creates a new Etcd Provider
func New(addr string) (provider.Provider, error) {
	p, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}

	cfg := client.Config{
		Endpoints: p.endpoints,
		Transport: client.DefaultTransport,
		Username:  p.username,
		Password:  p.password,
	}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	p.KeysAPI = client.NewKeysAPI(c)
	return p, nil
}

// Hosts satisfies provider.Provider interface.
func (p *Provider) Hosts() ([]string, error) {
	var hosts []string
	resp, err := p.Get(context.Background(), p.directory, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Node.Dir {
		return nil, fmt.Errorf("%s is %v", p.directory, errNotDirectory)
	}
	for _, node := range resp.Node.Nodes {
		if node.Dir {
			return nil, fmt.Errorf("%s is %v", node.Key, errNotKey)
		}
		hosts = append(hosts, node.Value)
	}
	return hosts, nil
}

// Watch satisfies provider.DynamicProvider interface.
func (p *Provider) Watch() provider.Watcher {
	w := p.Watcher(p.directory, &client.WatcherOptions{Recursive: true})
	return &watcher{
		next: func() (msg provider.WatcherMsg, err error) {
			var resp *client.Response
			if resp, err = w.Next(context.Background()); err != nil {
				return
			}
			if resp.Node.Dir {
				err = fmt.Errorf("%s is %v", resp.Node.Key, errNotKey)
				return
			}
			if len(strings.Split(strings.TrimPrefix(resp.Node.Key, p.directory), "/")) != 1 {
				err = fmt.Errorf("%s is %v '%v", resp.Node.Key, errNotInDirectory, p.directory)
				return
			}

			// Remove host
			if resp.Node.Value == "" {
				if resp.PrevNode != nil {
					return provider.WatcherMsg{Host: resp.PrevNode.Value, Remove: true}, nil
				}
				// should not happen
				err = errors.New("Node is previously empty")
			}

			// Add host
			return provider.WatcherMsg{Host: resp.Node.Value, Remove: false}, err
		},
	}
}

type watcher struct {
	next func() (provider.WatcherMsg, error)
}

func (w *watcher) Next() (provider.WatcherMsg, error) {
	return w.next()
}

// parseAddr passes addr into a new configured Provider.
// URL format: etcd://username:password@<etcd_addr1>,<etcd_addr2>/<optional path prefix>
func parseAddr(addr string) (*Provider, error) {
	p := &Provider{}

	u, err := url.Parse(addr)
	if err != nil {
		return p, err
	}

	if u.Scheme != Scheme {
		return nil, errInvalidScheme
	}

	p.directory = DefaultDirectory
	if u.Path != "" && u.Path != "/" {
		p.directory = u.Path
	}
	for _, endpoint := range strings.Split(u.Host, ",") {
		p.endpoints = append(p.endpoints, "http://"+endpoint)
	}
	if u.User != nil {
		p.username = u.User.Username()
		p.password, _ = u.User.Password()
	}
	return p, nil
}
