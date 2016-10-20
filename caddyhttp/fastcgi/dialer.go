package fastcgi

import (
	"errors"
	"sync"
	"sync/atomic"
)

type dialer interface {
	Dial() (Client, error)
	Close(Client) error
}

// basicDialer is a basic dialer that wraps default fcgi functions.
type basicDialer struct {
	network, address string
}

func (b basicDialer) Dial() (Client, error) { return Dial(b.network, b.address) }
func (b basicDialer) Close(c Client) error  { return c.Close() }

// persistentDialer keeps a pool of fcgi connections.
// connections are not closed after use, rather added back to the pool for reuse.
type persistentDialer struct {
	size    int
	network string
	address string
	pool    []Client
	sync.Mutex
}

func (p *persistentDialer) Dial() (Client, error) {
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

func (p *persistentDialer) Close(client Client) error {
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

type loadBalancingDialer struct {
	dialers []dialer
	current int64
}

func (m *loadBalancingDialer) Dial() (Client, error) {
	nextDialerIndex := atomic.AddInt64(&m.current, 1) % int64(len(m.dialers))
	currentDialer := m.dialers[nextDialerIndex]

	if client, err := currentDialer.Dial(); err != nil {
		return nil, err
	} else {
		return &dialerAwareClient{Client: client, dialer: currentDialer}, nil
	}
}

func (m *loadBalancingDialer) Close(c Client) error {
	// Close the client according to dialer behaviour
	if da, ok := c.(*dialerAwareClient); ok {
		return da.dialer.Close(c)
	}

	return errors.New("Cannot close client")
}

type dialerAwareClient struct {
	Client
	dialer dialer
}
