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

// SiteData contains persisted items pertaining to an individual site.
type SiteData struct {
	// Cert is the public cert byte array.
	Cert []byte
	// Key is the private key byte array.
	Key []byte
	// Meta is metadata about the site used by Caddy.
	Meta []byte
}

// UserData contains persisted items pertaining to a user.
type UserData struct {
	// Reg is the user registration byte array.
	Reg []byte
	// Key is the user key byte array.
	Key []byte
}

// Storage is an interface abstracting all storage used by Caddy's TLS
// subsystem. Implementations of this interface store both site and
// user data.
type Storage interface {
	// SiteExists returns true if this site exists in storage.
	// Site data is considered present when StoreSite has been called
	// successfully (without DeleteSite having been called, of course).
	SiteExists(domain string) (bool, error)

	// LoadSite obtains the site data from storage for the given domain and
	// returns it. If data for the domain does not exist, the
	// ErrStorageNotFound error instance is returned. For multi-server
	// storage, care should be taken to make this load atomic to prevent
	// race conditions that happen with multiple data loads.
	LoadSite(domain string) (*SiteData, error)

	// StoreSite persists the given site data for the given domain in
	// storage. For multi-server storage, care should be taken to make this
	// call atomic to prevent half-written data on failure of an internal
	// intermediate storage step. Implementers can trust that at runtime
	// this function will only be invoked after LockRegister and before
	// UnlockRegister of the same domain.
	StoreSite(domain string, data *SiteData) error

	// DeleteSite deletes the site for the given domain from storage.
	// Multi-server implementations should attempt to make this atomic. If
	// the site does not exist, the ErrStorageNotFound error instance is
	// returned.
	DeleteSite(domain string) error

	// LockRegister is called before Caddy attempts to obtain or renew a
	// certificate. This function is used as a mutex/semaphore for making
	// sure something else isn't already attempting obtain/renew. It should
	// return true (without error) if the lock is successfully obtained
	// meaning nothing else is attempting renewal. It should return false
	// (without error) if this domain is already locked by something else
	// attempting renewal. As a general rule, if this isn't multi-server
	// shared storage, this should always return true. To prevent deadlocks
	// for multi-server storage, all internal implementations should put a
	// reasonable expiration on this lock in case UnlockRegister is unable to
	// be called due to system crash. Errors should only be returned in
	// exceptional cases. Any error will prevent renewal.
	LockRegister(domain string) (bool, error)

	// UnlockRegister is called after Caddy has attempted to obtain or renew
	// a certificate, regardless of whether it was successful. If
	// LockRegister essentially just returns true because this is not
	// multi-server storage, this can be a no-op. Otherwise this should
	// attempt to unlock the lock obtained in this process by LockRegister.
	// If no lock exists, the implementation should not return an error. An
	// error is only for exceptional cases.
	UnlockRegister(domain string) error

	// LoadUser obtains user data from storage for the given email and
	// returns it. If data for the email does not exist, the
	// ErrStorageNotFound error instance is returned. Multi-server
	// implementations should take care to make this operation atomic for
	// all loaded data items.
	LoadUser(email string) (*UserData, error)

	// StoreUser persists the given user data for the given email in
	// storage. Multi-server implementations should take care to make this
	// operation atomic for all stored data items.
	StoreUser(email string, data *UserData) error

	// MostRecentUserEmail provides the most recently used email parameter
	// in StoreUser. The result is an empty string if there are no
	// persisted users in storage.
	MostRecentUserEmail() string
}
