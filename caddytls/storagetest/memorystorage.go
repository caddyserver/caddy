package storagetest

import (
	"github.com/mholt/caddy/caddytls"
	"net/url"
	"sync"
)

// memoryMutex is a mutex used to control access to memoryStoragesByCAURL.
var memoryMutex sync.Mutex

// memoryStoragesByCAURL is a map keyed by a CA URL string with values of
// instantiated memory stores. Do not access this directly, it is used by
// InMemoryStorageCreator.
var memoryStoragesByCAURL = make(map[string]*InMemoryStorage)

// InMemoryStorageCreator is a caddytls.Storage.StorageCreator to create
// InMemoryStorage instances for testing.
func InMemoryStorageCreator(caURL *url.URL) (caddytls.Storage, error) {
	urlStr := caURL.String()
	memoryMutex.Lock()
	defer memoryMutex.Unlock()
	storage := memoryStoragesByCAURL[urlStr]
	if storage == nil {
		storage = NewInMemoryStorage()
		memoryStoragesByCAURL[urlStr] = storage
	}
	return storage, nil
}

// InMemoryStorage is a caddytls.Storage implementation for use in testing.
// It simply stores information in runtime memory.
type InMemoryStorage struct {
	siteCerts     map[string][]byte
	siteKeys      map[string][]byte
	siteMetas     map[string][]byte
	userRegs      map[string][]byte
	userKeys      map[string][]byte
	lastUserEmail string
}

// NewInMemoryStorage constructs an InMemoryStorage instance. For use with
// caddytls, the InMemoryStorageCreator should be used instead.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		siteCerts: make(map[string][]byte),
		siteKeys:  make(map[string][]byte),
		siteMetas: make(map[string][]byte),
		userRegs:  make(map[string][]byte),
		userKeys:  make(map[string][]byte),
	}
}

// SiteInfoExists implements caddytls.Storage.SiteInfoExists in memory.
func (s *InMemoryStorage) SiteInfoExists(domain string) bool {
	_, siteCertExists := s.siteCerts[domain]
	_, siteKeyExists := s.siteKeys[domain]
	return siteCertExists && siteKeyExists
}

// loadFromMap loads from a map, taking care to error with ErrStorageNotFound
// as needed.
func loadFromMap(key string, m map[string][]byte) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, caddytls.ErrStorageNotFound
	}
	return v, nil
}

// storeInMap stores in a map, taking care to copy the bytes instead of keeping
// the slice reference.
func storeInMap(key string, value []byte, m map[string][]byte) {
	copiedBytes := make([]byte, len(value))
	copy(copiedBytes, value)
	m[key] = copiedBytes
}

// Clear completely clears all values associated with this storage.
func (s *InMemoryStorage) Clear() {
	s.siteCerts = make(map[string][]byte)
	s.siteKeys = make(map[string][]byte)
	s.siteMetas = make(map[string][]byte)
	s.userRegs = make(map[string][]byte)
	s.userKeys = make(map[string][]byte)
	s.lastUserEmail = ""
}

// LoadSiteCert implements caddytls.Storage.LoadSiteCert in memory.
func (s *InMemoryStorage) LoadSiteCert(domain string) ([]byte, error) {
	return loadFromMap(domain, s.siteCerts)
}

// StoreSiteCert implements caddytls.Storage.StoreSiteCert in memory.
func (s *InMemoryStorage) StoreSiteCert(domain string, byts []byte) error {
	storeInMap(domain, byts, s.siteCerts)
	return nil
}

// DeleteSiteCert implements caddytls.Storage.DeleteSiteCert in memory.
func (s *InMemoryStorage) DeleteSiteCert(domain string) error {
	if _, ok := s.siteCerts[domain]; !ok {
		return caddytls.ErrStorageNotFound
	}
	delete(s.siteCerts, domain)
	return nil
}

// LoadSiteKey implements caddytls.Storage.LoadSiteKey in memory.
func (s *InMemoryStorage) LoadSiteKey(domain string) ([]byte, error) {
	return loadFromMap(domain, s.siteKeys)
}

// StoreSiteKey implements caddytls.Storage.StoreSiteKey in memory.
func (s *InMemoryStorage) StoreSiteKey(domain string, byts []byte) error {
	storeInMap(domain, byts, s.siteKeys)
	return nil
}

// LoadSiteMeta implements caddytls.Storage.LoadSiteMeta in memory.
func (s *InMemoryStorage) LoadSiteMeta(domain string) ([]byte, error) {
	return loadFromMap(domain, s.siteMetas)
}

// StoreSiteMeta implements caddytls.Storage.StoreSiteMeta in memory.
func (s *InMemoryStorage) StoreSiteMeta(domain string, byts []byte) error {
	storeInMap(domain, byts, s.siteMetas)
	return nil
}

// LoadUserReg implements caddytls.Storage.LoadUserReg in memory.
func (s *InMemoryStorage) LoadUserReg(email string) ([]byte, error) {
	return loadFromMap(email, s.userRegs)
}

// StoreUserReg implements caddytls.Storage.StoreUserReg in memory.
func (s *InMemoryStorage) StoreUserReg(email string, byts []byte) error {
	storeInMap(email, byts, s.userRegs)
	s.lastUserEmail = email
	return nil
}

// LoadUserKey implements caddytls.Storage.LoadUserKey in memory.
func (s *InMemoryStorage) LoadUserKey(email string) ([]byte, error) {
	return loadFromMap(email, s.userKeys)
}

// StoreUserKey implements caddytls.Storage.StoreUserKey in memory.
func (s *InMemoryStorage) StoreUserKey(email string, byts []byte) error {
	storeInMap(email, byts, s.userKeys)
	s.lastUserEmail = email
	return nil
}

// MostRecentUserEmail implements caddytls.Storage.MostRecentUserEmail in memory.
func (s *InMemoryStorage) MostRecentUserEmail() string {
	return s.lastUserEmail
}
