package fastcgi

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type dialer interface {
	Dial() (Client, error)
	Close(Client) error
}

// basicDialer is a basic dialer that wraps default fcgi functions.
type basicDialer struct {
	network string
	address string
	timeout time.Duration
}

func (b basicDialer) Dial() (Client, error) {
	return DialTimeout(b.network, b.address, b.timeout)
}

func (b basicDialer) Close(c Client) error { return c.Close() }

// persistentDialer keeps a pool of fcgi connections.
// connections are not closed after use, rather added back to the pool for reuse.
type persistentDialer struct {
	size    int
	network string
	address string
	timeout time.Duration
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
	return DialTimeout(p.network, p.address, p.timeout)
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
	current int64
	dialers []dialer
}

func (m *loadBalancingDialer) Dial() (Client, error) {
	nextDialerIndex := atomic.AddInt64(&m.current, 1) % int64(len(m.dialers))
	currentDialer := m.dialers[nextDialerIndex]

	client, err := currentDialer.Dial()

	if err != nil {
		return nil, err
	}

	return &dialerAwareClient{Client: client, dialer: currentDialer}, nil
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
