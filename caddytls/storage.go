package caddytls

import (
	"errors"
	"net/url"
)

var (
	ErrStorageNotFound = errors.New("cert not found")
)

type StorageCreator func(caURL *url.URL) (Storage, error)

// Expected to be thread safe...
type Storage interface {
	SiteInStorage(domain string) bool

	LoadSiteCert(domain string) ([]byte, error)
	StoreSiteCert(domain string, byts []byte) error
	DeleteSiteCert(domain string) error

	LoadSiteKey(domain string) ([]byte, error)
	StoreSiteKey(domain string, byts []byte) error

	LoadSiteMeta(domain string) ([]byte, error)
	StoreSiteMeta(domain string, byts []byte) error

	LoadUserReg(email string) ([]byte, error)
	StoreUserReg(email string, byts []byte) error

	LoadUserKey(email string) ([]byte, error)
	StoreUserKey(email string, byts []byte) error

	MostRecentUserEmail() string
}
