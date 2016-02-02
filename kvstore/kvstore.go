package kvstore

import (
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/consul"
	"github.com/docker/libkv/store/etcd"
	"github.com/docker/libkv/store/zookeeper"
)

const (
	Timeout          = 10 * time.Second
	DefaultDirectory = "caddyserver.com/"
)

func init() {
	// Register backends
	consul.Register()
	etcd.Register()
	zookeeper.Register()
}

type Store struct {
	store.Store
	Type    string // Backend
	BaseDir string // Base directory
}

func NewStore(addr string) (*Store, error) {
	s := new(Store)
	u, err := url.Parse(addr)
	if err != nil {
		return s, err
	}

	config := &store.Config{
		ConnectionTimeout: Timeout,
	}

	s.BaseDir = DefaultDirectory
	s.Type = u.Scheme
	if u.Path != "" && u.Path != "/" {
		s.BaseDir = u.Path[1:]
	}

	var endpoints []string
	for _, endpoint := range strings.Split(u.Host, ",") {
		endpoints = append(endpoints, endpoint)
	}

	s.Store, err = libkv.NewStore(store.Backend(u.Scheme), endpoints, config)

	return s, err
}

func (s Store) Key(key string) string {
	return path.Join(s.BaseDir, key)
}
