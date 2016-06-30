package caddytls

import "net/url"

func InMemoryStorageCreator(caURL *url.URL) (Storage, error) {
	return &inMemoryStorage{
		siteCerts: map[string][]byte{},
		siteKeys:  map[string][]byte{},
		siteMetas: map[string][]byte{},
		userRegs:  map[string][]byte{},
		userKeys:  map[string][]byte{},
	}, nil
}

type inMemoryStorage struct {
	siteCerts     map[string][]byte
	siteKeys      map[string][]byte
	siteMetas     map[string][]byte
	userRegs      map[string][]byte
	userKeys      map[string][]byte
	lastUserEmail string
}

func (s *inMemoryStorage) SiteInStorage(domain string) bool {
	_, ok := s.siteCerts[domain]
	return ok
}

func loadFromMap(key string, m map[string][]byte) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, ErrStorageNotFound
	}
	return v, nil
}

func (s *inMemoryStorage) LoadSiteCert(domain string) ([]byte, error) {
	return loadFromMap(domain, s.siteCerts)
}

func (s *inMemoryStorage) StoreSiteCert(domain string, byts []byte) error {
	s.siteCerts[domain] = byts
	return nil
}

func (s *inMemoryStorage) DeleteSiteCert(domain string) error {
	delete(s.siteCerts, domain)
	return nil
}

func (s *inMemoryStorage) LoadSiteKey(domain string) ([]byte, error) {
	return loadFromMap(domain, s.siteKeys)
}

func (s *inMemoryStorage) StoreSiteKey(domain string, byts []byte) error {
	s.siteKeys[domain] = byts
	return nil
}

func (s *inMemoryStorage) LoadSiteMeta(domain string) ([]byte, error) {
	return loadFromMap(domain, s.siteMetas)
}

func (s *inMemoryStorage) StoreSiteMeta(domain string, byts []byte) error {
	s.siteMetas[domain] = byts
	return nil
}

func (s *inMemoryStorage) LoadUserReg(email string) ([]byte, error) {
	return loadFromMap(email, s.userRegs)
}

func (s *inMemoryStorage) StoreUserReg(email string, byts []byte) error {
	s.userRegs[email] = byts
	s.lastUserEmail = email
	return nil
}

func (s *inMemoryStorage) LoadUserKey(email string) ([]byte, error) {
	return loadFromMap(email, s.userKeys)
}

func (s *inMemoryStorage) StoreUserKey(email string, byts []byte) error {
	s.userKeys[email] = byts
	return nil
}

func (s *inMemoryStorage) MostRecentUserEmail() string {
	return s.lastUserEmail
}
