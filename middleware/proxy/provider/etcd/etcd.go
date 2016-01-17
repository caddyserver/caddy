package etcd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/etcd/client"
	"github.com/mholt/caddy/middleware/proxy/provider"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"golang.org/x/net/context"
)

const (
	Scheme = "etcd://"

	DefaultDirectory = "/CADDY_PROXY_HOSTS/"
)

var (
	ErrInvalidScheme  = errors.New("invalid Etcd scheme")
	ErrNotDirectory   = errors.New("not an Etcd directory")
	ErrNotKey         = errors.New("not an Etcd key")
	ErrNotInDirectory = errors.New("not in expected directory")
)

type Provider struct {
	endpoints []string
	directory string
	username  string
	password  string
	client.KeysAPI
	sync.Mutex
}

// New creates a new Etcd DynamicProvider
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
	return &p, nil
}

func (p *Provider) Hosts() ([]string, error) {
	var hosts []string
	resp, err := p.Get(context.Background(), p.directory, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Node.Dir {
		return nil, fmt.Errorf("%s is %v", p.directory, ErrNotDirectory)
	}
	for _, node := range resp.Node.Nodes {
		if node.Dir {
			return nil, fmt.Errorf("%s is %v", node.Key, ErrNotKey)
		}
		hosts = append(hosts, node.Value)
	}
	return hosts, nil
}

func (p *Provider) Watch() provider.Watcher {
	w := p.Watcher(p.directory, &client.WatcherOptions{Recursive: true})
	return &watcher{
		next: func() (msg provider.WatcherMsg, err error) {
			var resp *client.Response
			if resp, err = w.Next(context.Background()); err != nil {
				return
			}
			if resp.Node.Dir {
				err = fmt.Errorf("%s is %v", resp.Node.Key, ErrNotKey)
				return
			}
			if len(strings.Split(strings.TrimPrefix(resp.Node.Key, p.directory), "/")) != 1 {
				err = fmt.Errorf("%s is %v '%v", resp.Node.Key, ErrNotInDirectory, p.directory)
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

// URL format
// etcd://username:password@<etcd_addr1>,<etcd_addr2>/<optional path prefix>
func parseAddr(addr string) (Provider, error) {
	p := Provider{}
	if !strings.HasPrefix(addr, Scheme) {
		return p, ErrInvalidScheme
	}
	p.username, p.password, addr = extractUserPass(strings.TrimPrefix(addr, Scheme))
	s := strings.SplitN(addr, "/", 2)
	for _, v := range strings.Split(s[0], ",") {
		p.endpoints = append(p.endpoints, "http://"+v)
	}
	if len(s) == 2 {
		p.directory = "/" + s[1]
		if !strings.HasSuffix(s[1], "/") {
			p.directory += "/"
		}
	} else {
		p.directory = DefaultDirectory
	}
	return p, nil
}

func extractUserPass(addr string) (username, password, remaining string) {
	s := strings.SplitN(addr, "@", 2)
	if len(s) == 1 {
		remaining = addr
		return
	}
	userPass := strings.Split(s[0], ":")
	username = userPass[0]
	if len(userPass) > 1 {
		password = userPass[1]
	}
	remaining = s[1]
	return
}
