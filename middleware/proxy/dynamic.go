package proxy

import (
	"github.com/mholt/caddy/middleware/proxy/provider"
	"github.com/mholt/caddy/middleware/proxy/provider/etcd"
)

func init() {
	// register dynamic providers
	provider.Register("etcd", etcd.New)
}
