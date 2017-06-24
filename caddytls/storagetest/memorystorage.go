package storagetest

import (
	"errors"
	"net/url"
	"sync"

	"github.com/mholt/caddy/caddytls"
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
	// Sites are exposed for testing purposes.
	Sites map[string]*caddytls.SiteData
	// Users are exposed for testing purposes.
	Users map[string]*caddytls.UserData
	// LastUserEmail is exposed for testing purposes.
	LastUserEmail string
}

// NewInMemoryStorage constructs an InMemoryStorage instance. For use with
// caddytls, the InMemoryStorageCreator should be used instead.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		Sites: make(map[string]*caddytls.SiteData),
		Users: make(map[string]*caddytls.UserData),
	}
}

// SiteExists implements caddytls.Storage.SiteExists in memory.
func (s *InMemoryStorage) SiteExists(domain string) (bool, error) {
	_, siteExists := s.Sites[domain]
	return siteExists, nil
}

// Clear completely clears all values associated with this storage.
func (s *InMemoryStorage) Clear() {
	s.Sites = make(map[string]*caddytls.SiteData)
	s.Users = make(map[string]*caddytls.UserData)
	s.LastUserEmail = ""
}

// LoadSite implements caddytls.Storage.LoadSite in memory.
func (s *InMemoryStorage) LoadSite(domain string) (*caddytls.SiteData, error) {
	siteData, ok := s.Sites[domain]
	if !ok {
		return nil, caddytls.ErrNotExist(errors.New("not found"))
	}
	return siteData, nil
}

func copyBytes(from []byte) []byte {
	copiedBytes := make([]byte, len(from))
	copy(copiedBytes, from)
	return copiedBytes
}

// StoreSite implements caddytls.Storage.StoreSite in memory.
func (s *InMemoryStorage) StoreSite(domain string, data *caddytls.SiteData) error {
	copiedData := new(caddytls.SiteData)
	copiedData.Cert = copyBytes(data.Cert)
	copiedData.Key = copyBytes(data.Key)
	copiedData.Meta = copyBytes(data.Meta)
	s.Sites[domain] = copiedData
	return nil
}

// DeleteSite implements caddytls.Storage.DeleteSite in memory.
func (s *InMemoryStorage) DeleteSite(domain string) error {
	if _, ok := s.Sites[domain]; !ok {
		return caddytls.ErrNotExist(errors.New("not found"))
	}
	delete(s.Sites, domain)
	return nil
}

// TryLock implements Storage.TryLock by returning nil values because it
// is not a multi-server storage implementation.
func (s *InMemoryStorage) TryLock(domain string) (caddytls.Waiter, error) {
	return nil, nil
}

// Unlock implements Storage.Unlock as a no-op because it is
// not a multi-server storage implementation.
func (s *InMemoryStorage) Unlock(domain string) error {
	return nil
}

// LoadUser implements caddytls.Storage.LoadUser in memory.
func (s *InMemoryStorage) LoadUser(email string) (*caddytls.UserData, error) {
	userData, ok := s.Users[email]
	if !ok {
		return nil, caddytls.ErrNotExist(errors.New("not found"))
	}
	return userData, nil
}

// StoreUser implements caddytls.Storage.StoreUser in memory.
func (s *InMemoryStorage) StoreUser(email string, data *caddytls.UserData) error {
	copiedData := new(caddytls.UserData)
	copiedData.Reg = copyBytes(data.Reg)
	copiedData.Key = copyBytes(data.Key)
	s.Users[email] = copiedData
	s.LastUserEmail = email
	return nil
}

// MostRecentUserEmail implements caddytls.Storage.MostRecentUserEmail in memory.
func (s *InMemoryStorage) MostRecentUserEmail() string {
	return s.LastUserEmail
}
