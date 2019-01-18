// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Storage is a type that implements a key-value store.
// Keys are prefix-based, with forward slash '/' as separators
// and without a leading slash.
//
// Processes running in a cluster will wish to use the
// same Storage value (its implementation and configuration)
// in order to share certificates and other TLS resources
// with the cluster.
//
// Implementations of Storage must be safe for concurrent use.
type Storage interface {
	// Locker provides atomic synchronization
	// operations, making Storage safe to share.
	Locker

	// Store puts value at key.
	Store(key string, value []byte) error

	// Load retrieves the value at key.
	Load(key string) ([]byte, error)

	// Delete deletes key.
	Delete(key string) error

	// Exists returns true if the key exists
	// and there was no error checking.
	Exists(key string) bool

	// List returns all keys that match prefix.
	// If recursive is true, non-terminal keys
	// will be enumerated (i.e. "directories"
	// should be walked); otherwise, only keys
	// prefixed exactly by prefix will be listed.
	List(prefix string, recursive bool) ([]string, error)

	// Stat returns information about key.
	Stat(key string) (KeyInfo, error)
}

// Locker facilitates synchronization of certificate tasks across
// machines and networks.
type Locker interface {
	// Lock acquires the lock for key, blocking until the lock
	// can be obtained or an error is returned. Note that, even
	// after acquiring a lock, an idempotent operation may have
	// already been performed by another process that acquired
	// the lock before - so always check to make sure idempotent
	// operations still need to be performed after acquiring the
	// lock.
	//
	// The actual implementation of obtaining of a lock must be
	// an atomic operation so that multiple Lock calls at the
	// same time always results in only one caller receiving the
	// lock at any given time.
	//
	// To prevent deadlocks, all implementations (where this concern
	// is relevant) should put a reasonable expiration on the lock in
	// case Unlock is unable to be called due to some sort of network
	// or system failure or crash.
	Lock(key string) error

	// Unlock releases the lock for key. This method must ONLY be
	// called after a successful call to Lock, and only after the
	// critical section is finished, even if it errored or timed
	// out. Unlock cleans up any resources allocated during Lock.
	Unlock(key string) error
}

// KeyInfo holds information about a key in storage.
type KeyInfo struct {
	Key        string
	Modified   time.Time
	Size       int64
	IsTerminal bool // false for keys that only contain other keys (like directories)
}

// storeTx stores all the values or none at all.
func storeTx(s Storage, all []keyValue) error {
	for i, kv := range all {
		err := s.Store(kv.key, kv.value)
		if err != nil {
			for j := i - 1; j >= 0; j-- {
				s.Delete(all[j].key)
			}
			return err
		}
	}
	return nil
}

// keyValue pairs a key and a value.
type keyValue struct {
	key   string
	value []byte
}

// KeyBuilder provides a namespace for methods that
// build keys and key prefixes, for addressing items
// in a Storage implementation.
type KeyBuilder struct{}

// CAPrefix returns the storage key prefix for
// the given certificate authority URL.
func (keys KeyBuilder) CAPrefix(ca string) string {
	caURL, err := url.Parse(ca)
	if err != nil {
		caURL = &url.URL{Host: ca}
	}
	return path.Join(prefixACME, keys.Safe(caURL.Host))
}

// SitePrefix returns a key prefix for items associated with
// the site using the given CA URL.
func (keys KeyBuilder) SitePrefix(ca, domain string) string {
	return path.Join(keys.CAPrefix(ca), "sites", keys.Safe(domain))
}

// SiteCert returns the path to the certificate file for domain.
func (keys KeyBuilder) SiteCert(ca, domain string) string {
	return path.Join(keys.SitePrefix(ca, domain), keys.Safe(domain)+".crt")
}

// SitePrivateKey returns the path to domain's private key file.
func (keys KeyBuilder) SitePrivateKey(ca, domain string) string {
	return path.Join(keys.SitePrefix(ca, domain), keys.Safe(domain)+".key")
}

// SiteMeta returns the path to the domain's asset metadata file.
func (keys KeyBuilder) SiteMeta(ca, domain string) string {
	return path.Join(keys.SitePrefix(ca, domain), keys.Safe(domain)+".json")
}

// UsersPrefix returns a key prefix for items related to
// users associated with the given CA URL.
func (keys KeyBuilder) UsersPrefix(ca string) string {
	return path.Join(keys.CAPrefix(ca), "users")
}

// UserPrefix returns a key prefix for items related to
// the user with the given email for the given CA URL.
func (keys KeyBuilder) UserPrefix(ca, email string) string {
	if email == "" {
		email = emptyEmail
	}
	return path.Join(keys.UsersPrefix(ca), keys.Safe(email))
}

// UserReg gets the path to the registration file for the user
// with the given email address for the given CA URL.
func (keys KeyBuilder) UserReg(ca, email string) string {
	return keys.safeUserKey(ca, email, "registration", ".json")
}

// UserPrivateKey gets the path to the private key file for the
// user with the given email address on the given CA URL.
func (keys KeyBuilder) UserPrivateKey(ca, email string) string {
	return keys.safeUserKey(ca, email, "private", ".key")
}

// OCSPStaple returns a key for the OCSP staple associated
// with the given certificate. If you have the PEM bundle
// handy, pass that in to save an extra encoding step.
func (keys KeyBuilder) OCSPStaple(cert *Certificate, pemBundle []byte) string {
	var ocspFileName string
	if len(cert.Names) > 0 {
		firstName := keys.Safe(cert.Names[0])
		ocspFileName = firstName + "-"
	}
	ocspFileName += fastHash(pemBundle)
	return path.Join(prefixOCSP, ocspFileName)
}

// safeUserKey returns a key for the given email, with the default
// filename, and the filename ending in the given extension.
func (keys KeyBuilder) safeUserKey(ca, email, defaultFilename, extension string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	filename := keys.emailUsername(email)
	if filename == "" {
		filename = defaultFilename
	}
	filename = keys.Safe(filename)
	return path.Join(keys.UserPrefix(ca, email), filename+extension)
}

// emailUsername returns the username portion of an email address (part before
// '@') or the original input if it can't find the "@" symbol.
func (keys KeyBuilder) emailUsername(email string) string {
	at := strings.Index(email, "@")
	if at == -1 {
		return email
	} else if at == 0 {
		return email[1:]
	}
	return email[:at]
}

// Safe standardizes and sanitizes str for use as
// a storage key. This method is idempotent.
func (keys KeyBuilder) Safe(str string) string {
	str = strings.ToLower(str)
	str = strings.TrimSpace(str)

	// replace a few specific characters
	repl := strings.NewReplacer(
		" ", "_",
		"+", "_plus_",
		"*", "wildcard_",
		"..", "", // prevent directory traversal (regex allows single dots)
	)
	str = repl.Replace(str)

	// finally remove all non-word characters
	return safeKeyRE.ReplaceAllLiteralString(str, "")
}

// StorageKeys provides methods for accessing
// keys and key prefixes for items in a Storage.
// Typically, you will not need to use this
// because accessing storage is abstracted away
// for most cases. Only use this if you need to
// directly access TLS assets in your application.
var StorageKeys KeyBuilder

const (
	prefixACME = "acme"
	prefixOCSP = "ocsp"
)

// safeKeyRE matches any undesirable characters in storage keys.
// Note that this allows dots, so you'll have to strip ".." manually.
var safeKeyRE = regexp.MustCompile(`[^\w@.-]`)

// ErrNotExist is returned by Storage implementations when
// a resource is not found. It is similar to os.IsNotExist
// except this is a type, not a variable.
type ErrNotExist interface {
	error
}

// defaultFileStorage is a convenient, default storage
// implementation using the local file system.
var defaultFileStorage = &FileStorage{Path: dataDir()}

// DefaultStorage is the default Storage implementation.
var DefaultStorage Storage = defaultFileStorage
