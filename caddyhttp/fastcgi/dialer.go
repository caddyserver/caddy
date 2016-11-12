package fastcgi

import (
	"sync"
	"time"
)

type dialer interface {
	Dial() (*FCGIClient, error)
	Close(*FCGIClient) error
}

// basicDialer is a basic dialer that wraps default fcgi functions.
type basicDialer struct {
	network string
	address string
	timeout time.Duration
}

func (b basicDialer) Dial() (*FCGIClient, error) { return Dial(b.network, b.address, b.timeout) }
func (b basicDialer) Close(c *FCGIClient) error  { return c.Close() }

// persistentDialer keeps a pool of fcgi connections.
// connections are not closed after use, rather added back to the pool for reuse.
type persistentDialer struct {
	size    int
	network string
	address string
	timeout time.Duration
	pool    []*FCGIClient
	sync.Mutex
}

func (p *persistentDialer) Dial() (*FCGIClient, error) {
	p.Lock()
	// connection is available, return first one.
	if len(p.pool) > 0 {
		client := p.pool[0]
		p.pool = p.pool[1:]
		p.Unlock()

		return client, nil
	}

	p.Unlock()

	// no connection available, create new one
	return Dial(p.network, p.address, p.timeout)
}

func (p *persistentDialer) Close(client *FCGIClient) error {
	p.Lock()
	if len(p.pool) < p.size {
		// pool is not full yet, add connection for reuse
		p.pool = append(p.pool, client)
		p.Unlock()

		return nil
	}

	p.Unlock()

	// otherwise, close the connection.
	return client.Close()
}
