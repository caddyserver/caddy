package digestauth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type simpleNonce struct {
	mutex        sync.Mutex
	value        string
	next         Nonce
	expired      bool
	graceUses    int // after expired, decremented on each expire() called from AcceptCounter()
	countersSeen map[uint]bool
}

func newSimpleNonce() (Nonce, error) {
	size := 8 // 64 bits sounds good
	b := make([]byte, size)
	count, err := rand.Read(b)
	if count < size || err != nil {
		panic("rand.Read failed")
	}

	return &simpleNonce{value: hex.EncodeToString(b), countersSeen: map[uint]bool{}}, nil
}

func (n *simpleNonce) Value() string {
	// no lock, never changes
	return n.value
}

func (n *simpleNonce) Next() Nonce {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.next
}

func (n *simpleNonce) Stale() bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.expired && n.graceUses <= 0
}

func (n *simpleNonce) AcceptCounter(c uint) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.countersSeen[c] {
		return false
	}
	n.countersSeen[c] = true

	// Don't let our map get too big.
	if len(n.countersSeen) > 100 {
		n.Expire()
	}
	return true
}

func (n *simpleNonce) Expire() {
	if !n.expired {
		n.expired = true
		n.graceUses = 10
	} else {
		n.graceUses -= 1
	}
}
