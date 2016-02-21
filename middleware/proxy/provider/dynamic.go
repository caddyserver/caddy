package provider

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/docker/libkv/store"
	"github.com/mholt/caddy/kvstore"
)

var errWatchFailure = errors.New("WatchTree failed for")

// DynamicProvider is a dynamic hosts provider.
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
	Next() (msgs []WatcherMsg, err error)
}

// dynamic creates a new dynamic host provider.
func dynamic(addr string) (Provider, error) {
	store, err := kvstore.NewStore(addr)
	if err != nil {
		return nil, err
	}
	return &dynamicProvider{
		Store: store,
		hosts: make(map[string]struct{}),
	}, nil
}

type dynamicProvider struct {
	hosts map[string]struct{}
	*kvstore.Store
}

// Hosts satisfy Provider.
func (d *dynamicProvider) Hosts() ([]string, error) {
	var hosts []string

	// create directory if not exists
	if ok, _ := d.Exists(d.BaseDir); !ok {
		err := d.Put(d.Key(""), nil, &store.WriteOptions{IsDir: true})
		if err != nil {
			return hosts, err
		}
	}

	kvs, err := d.List(d.BaseDir)
	if err != nil {
		return hosts, err
	}
	for _, kv := range kvs {
		host := string(kv.Value)
		hosts = append(hosts, host)
		d.hosts[host] = struct{}{}
	}
	return hosts, nil
}

// Watch satisfies DynamicProvider.
func (d *dynamicProvider) Watch() Watcher {
	keysChan, err := d.WatchTree(d.BaseDir, nil)
	if err != nil {
		log.Println(err)
		return nil
	}

	var m sync.Mutex
	return &watcher{
		next: func() ([]WatcherMsg, error) {
			m.Lock()
			defer m.Unlock()

			var msgs []WatcherMsg

			keys, ok := <-keysChan
			if !ok {
				// attempt to resurrect the closed channel ahead of next retry.
				if keysChan, err = d.WatchTree(d.BaseDir, nil); err != nil {
					// return watcher's error message
					return msgs, err
				}
				// return generic error message, next try will be successful.
				return msgs, fmt.Errorf("%v %s", errWatchFailure, d.Type)
			}

			// comparison set
			hosts := make(map[string]struct{})

			// additions. hosts not in existing provider set.
			for _, key := range keys {
				host := string(key.Value)
				if _, ok := d.hosts[host]; !ok {
					msgs = append(msgs, WatcherMsg{Host: host})
					d.hosts[host] = struct{}{}
				}
				// populate comparison set
				hosts[host] = struct{}{}
			}

			// removals, hosts not in new comparison set but in provider set.
			for host, _ := range d.hosts {
				if _, ok := hosts[host]; !ok {
					msgs = append(msgs, WatcherMsg{Host: host, Remove: true})
				}
			}
			return msgs, nil
		},
	}
}

type watcher struct {
	next func() ([]WatcherMsg, error)
}

func (w *watcher) Next() ([]WatcherMsg, error) {
	return w.next()
}
