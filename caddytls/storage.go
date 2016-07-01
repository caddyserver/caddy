package caddytls

import (
	"errors"
	"net/url"
)

// ErrStorageNotFound is returned by Storage implementations when data is
// expected to be present but is not.
var ErrStorageNotFound = errors.New("data not found")

// StorageCreator is a function type that is used in the Config to instantiate
// a new Storage instance. This function can return a nil Storage even without
// an error.
type StorageCreator func(caURL *url.URL) (Storage, error)

// Storage is an interface abstracting all storage used by the Caddy's TLS
// subsystem. Implementations of this interface store site certs, keys,
// metadata along with user metadata and keys.
type Storage interface {

	// SiteInfoExists returns true if this site info exists in storage.
	// Site info is considered present when StoreSiteCert and StoreSiteKey
	// have both been called successfully (without DeleteSiteCert having
	// been called of course).
	SiteInfoExists(domain string) bool

	// LoadSiteCert obtains the cert from storage for the given domain and
	// returns it as a set of bytes. If data for the domain does not exist,
	// the ErrStorageNotFound error instance is returned.
	LoadSiteCert(domain string) ([]byte, error)

	// StoreSiteCert persists the given byte array for the given domain in
	// storage.
	StoreSiteCert(domain string, byts []byte) error

	// DeleteSiteCert removes the cert from storage for the given domain.
	DeleteSiteCert(domain string) error

	// LoadSiteKey obtains the key from storage for the given domain and
	// returns it as a set of bytes. If data for the domain does not exist,
	// the ErrStorageNotFound error instance is returned.
	LoadSiteKey(domain string) ([]byte, error)

	// StoreSiteKey persists the given byte array for the given domain in
	// storage.
	StoreSiteKey(domain string, byts []byte) error

	// LoadSiteMeta obtains metadata from storage for the given domain and
	// returns it as a set of bytes. If data for the domain does not exist,
	// the ErrStorageNotFound error instance is returned.
	LoadSiteMeta(domain string) ([]byte, error)

	// StoreSiteMeta persists the given byte array for the given domain in
	// storage.
	StoreSiteMeta(domain string, byts []byte) error

	// LoadUserReg obtains user metadata from storage for the given email
	// and returns it as a set of bytes. If data for the email does not
	// exist, the ErrStorageNotFound error instance is returned.
	LoadUserReg(email string) ([]byte, error)

	// StoreUserReg persists the given byte array for the given email in
	// storage.
	StoreUserReg(email string, byts []byte) error

	// LoadUserKey obtains the user key from storage for the given email
	// and returns it as a set of bytes. If data for the email does not
	// exist, the ErrStorageNotFound error instance is returned.
	LoadUserKey(email string) ([]byte, error)

	// StoreUserKey persists the given byte array for the given email in
	// storage.
	StoreUserKey(email string, byts []byte) error

	// MostRecentUserEmail provides the most recently used email parameter
	// in either StoreUserReg or StoreUserKey. The result is an empty
	// string if there are no persisted users in storage.
	MostRecentUserEmail() string
}
