package digestauth

import (
	"log"
	"sync"
	"testing"
	"time"
)

type simpleNonceStore struct {
	mutex              sync.Mutex
	nonces             map[string]Nonce
	elderlyNonces      map[string]Nonce
	expirationInterval time.Duration
	nextExpiration     time.Time
}

func newSimpleNonceStore() *simpleNonceStore {
	interval, _ := time.ParseDuration("5s")
	if interval == 0 {
		panic("Unable to parse duration")
	}

	return &simpleNonceStore{
		nonces:             map[string]Nonce{},
		elderlyNonces:      map[string]Nonce{},
		expirationInterval: interval,
		nextExpiration:     time.Now().Add(interval),
	}
}

func (s *simpleNonceStore) Add(nonce Nonce) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.nonces[nonce.Value()] = nonce

	return nil
}

func (s *simpleNonceStore) Lookup(value string) (Nonce, bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()

	// that second || part catches that the system clock has moved more than an interval into the past
	// we are going to need a new expiration time or we'd wait for a potentially very long time
	togo := s.nextExpiration.Sub(now).Seconds()
	if togo < 0 || togo > s.expirationInterval.Seconds() {
		if testing.Verbose() {
			log.Printf("expiring nonces, interval=%#v:", s.expirationInterval)
			for k, _ := range s.elderlyNonces {
				log.Printf("    %#v", k)
			}
		}
		s.elderlyNonces = s.nonces
		s.nonces = map[string]Nonce{}
		s.nextExpiration = now.Add(s.expirationInterval)
	}

	// look in the current ones
	if n, found := s.nonces[value]; found {
		return n, true, nil
	}

	// look in the elderly ones
	if en, found := s.elderlyNonces[value]; found {
		// still in use, move it to the current nonces
		s.nonces[value] = en

		// don't bother to purge it from elderly, just makes memory load and it
		// is about to go away.
		return en, true, nil
	}

	// not found
	return nil, false, nil
}
