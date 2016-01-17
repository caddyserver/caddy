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

	DefaultDirectory = "/CADDY_PROXY_HOSTS"
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
	client.KeysAPI
	watching bool
	sync.Mutex
}

// New creates a new Etcd DynamicProvider
func New(addr string) (provider.DynamicProvider, error) {
	store, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}

	cfg := client.Config{
		Endpoints: store.endpoints,
		Transport: client.DefaultTransport,
	}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	store.KeysAPI = client.NewKeysAPI(c)
	return &store
}

func (p *Provider) Hosts([]string, error) {
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
	w := p.Watcher(p.directory, client.WatcherOptions{Recursive: true})
	return watcher{
		next: func() <-chan provider.Config {
			ch := make(<-chan provider.Config)
			go func() {
				p.Lock()
				p.watching = true
				p.Unlock()

				for {
					resp, err := w.Next(context.Background())
					if err != nil {
						return "", err
					}
					if resp.Node.Dir {
						return "", fmt.Errorf("%s is %v", resp.Node.Key, ErrNotKey)
					}
					if len(strings.Split(strings.TrimPrefix(resp.Node.Key, p.directory), "/")) != 1 {
						return "", fmt.Errorf("%s is %v '%v", resp.Node.Key, ErrNotInDirectory, p.directory)
					}
					ch <- provider.Config{resp.Node.Value, nil}
					p.Lock()
					if !p.watching {
						p.Unlock()
						break
					}
					p.Unlock()
				}
			}()
			return ch
		},
		stop: func() {
			p.Lock()
			p.watching = false
			p.Unlock()
		},
	}
}

type watcher struct {
	next func() <-chan provider.Config
	stop func()
}

func (w watcher) Next() <-chan provider.Config {
	return w.next()
}

func (w watcher) Stop() {
	w.stop()
}

// URL format
// etcd://<etcd_addr1>,<etcd_addr2>/<optional path prefix>
func parseAddr(addr string) (Provider, error) {
	store := Provider{}
	if !strings.HasPrefix(addr, Scheme) {
		return ErrInvalidScheme
	}
	addr = strings.TrimPrefix(addr, Scheme)
	s := strings.SplitN(addr, "/", 2)
	for _, v := range strings.Split(s, ",") {
		store.endpoints = append(store.endpoints, "http://"+v)
	}
	if len(s) == 2 {
		store.directory = "/" + s[1]
	} else {
		store.directory = DefaultDirectory
	}
	return store, nil
}

func init() {
	// register
	provider.Register("etcd://", New)
}
