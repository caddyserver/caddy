package fastcgi

import "sync"

type dialer interface {
	Dial() (*FCGIClient, error)
	Close(*FCGIClient) error
}

// basicDialer is a basic dialer that wraps default fcgi functions.
type basicDialer struct {
	network, address string
}

func (b basicDialer) Dial() (*FCGIClient, error) { return Dial(b.network, b.address) }
func (b basicDialer) Close(c *FCGIClient) error  { return c.Close() }

// persistentDialer keeps a pool of fcgi connections.
// connections are not closed after use, rather added back to the pool for reuse.
type persistentDialer struct {
	size    int
	network string
	address string
	pool    []*FCGIClient
	sync.Mutex
}

func (p *persistentDialer) Equals(q *persistentDialer) bool {
	if p.size != q.size {
		return false
	}
	if p.network != q.network {
		return false
	}
	if p.address != q.address {
		return false
	}

	if len(p.pool) != len(q.pool) {
		return false
	}
	for i, client := range p.pool {
		if client != q.pool[i] {
			return false
		}
	}
	// ignore mutex state
	return true
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
	return Dial(p.network, p.address)
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
