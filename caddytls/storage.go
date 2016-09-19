package caddytls

import "net/url"

// StorageConstructor is a function type that is used in the Config to
// instantiate a new Storage instance. This function can return a nil
// Storage even without an error.
type StorageConstructor func(caURL *url.URL) (Storage, error)

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

	// TryLock is called before Caddy attempts to obtain or renew a
	// certificate for a certain name and store it. From the perspective
	// of this method and its companion Unlock, the actions of
	// obtaining/renewing and then storing the certificate are atomic,
	// and both should occur within a lock. This prevents multiple
	// processes -- maybe distributed ones -- from stepping on each
	// other's space in the same shared storage, and from spamming
	// certificate providers with multiple, redundant requests.
	//
	// If a lock could be obtained, (nil, nil) is returned and you may
	// continue normally. If not (meaning another process is already
	// working on that name), a Waiter value will be returned upon
	// which you can Wait() until it is finished, and then return
	// when it unblocks. If waiting, do not unlock!
	//
	// To prevent deadlocks, all implementations (where this concern
	// is relevant) should put a reasonable expiration on the lock in
	// case Unlock is unable to be called due to some sort of storage
	// system failure or crash.
	TryLock(name string) (Waiter, error)

	// Unlock unlocks the mutex for name. Only callers of TryLock who
	// successfully obtained the lock (no Waiter value was returned)
	// should call this method, and it should be called only after
	// the obtain/renew and store are finished, even if there was
	// an error (or a timeout).
	Unlock(name string) error

	// LoadSite obtains the site data from storage for the given domain and
	// returns it. If data for the domain does not exist, an error value
	// of type ErrNotExist is returned. For multi-server storage, care
	// should be taken to make this load atomic to prevent race conditions
	// that happen with multiple data loads.
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
	// the site does not exist, an error value of type ErrNotExist is returned.
	DeleteSite(domain string) error

	// LoadUser obtains user data from storage for the given email and
	// returns it. If data for the email does not exist, an error value
	// of type ErrNotExist is returned. Multi-server implementations
	// should take care to make this operation atomic for all loaded
	// data items.
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

// ErrNotExist is returned by Storage implementations when
// a resource is not found. It is similar to os.ErrNotExist
// except this is a type, not a variable.
type ErrNotExist interface {
	error
}

// Waiter is a type that can block until a storage lock is released.
type Waiter interface {
	Wait()
}
