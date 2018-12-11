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
	List(prefix string) ([]string, error)

	// Stat returns information about key.
	Stat(key string) (KeyInfo, error)
}

// Locker facilitates synchronization of certificate tasks across
// machines and networks.
type Locker interface {
	// TryLock will attempt to acquire the lock for key. If a
	// lock could be obtained, nil values are returned as no
	// waiting is required. If not (meaning another process is
	// already working on key), a Waiter value will be returned,
	// upon which you should Wait() until it is finished.
	//
	// The actual implementation of obtaining of a lock must be
	// an atomic operation so that multiple TryLock calls at the
	// same time always results in only one caller receiving the
	// lock. TryLock always returns without waiting.
	//
	// To prevent deadlocks, all implementations (where this concern
	// is relevant) should put a reasonable expiration on the lock in
	// case Unlock is unable to be called due to some sort of network
	// or system failure or crash.
	TryLock(key string) (Waiter, error)

	// Unlock releases the lock for key. This method must ONLY be
	// called after a successful call to TryLock where no Waiter was
	// returned, and only after the operation requiring the lock is
	// finished, even if it errored or timed out. It is INCORRECT to
	// call Unlock if any non-nil value was returned from a call to
	// TryLock or if Unlock was not called at all. Unlock should also
	// clean up any unused resources allocated during TryLock.
	Unlock(key string) error
}

// Waiter is a type that can block until a lock is released.
type Waiter interface {
	Wait()
}

// KeyInfo holds information about a key in storage.
type KeyInfo struct {
	Key      string
	Modified time.Time
	Size     int64
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

const (
	prefixACME = "acme"
	prefixOCSP = "ocsp"
)

func prefixCA(ca string) string {
	caURL, err := url.Parse(ca)
	if err != nil {
		caURL = &url.URL{Host: ca}
	}
	return path.Join(prefixACME, safeKey(caURL.Host))
}

func prefixSite(ca, domain string) string {
	return path.Join(prefixCA(ca), "sites", safeKey(domain))
}

// prefixSiteCert returns the path to the certificate file for domain.
func prefixSiteCert(ca, domain string) string {
	return path.Join(prefixSite(ca, domain), safeKey(domain)+".crt")
}

// prefixSiteKey returns the path to domain's private key file.
func prefixSiteKey(ca, domain string) string {
	return path.Join(prefixSite(ca, domain), safeKey(domain)+".key")
}

// prefixSiteMeta returns the path to the domain's asset metadata file.
func prefixSiteMeta(ca, domain string) string {
	return path.Join(prefixSite(ca, domain), safeKey(domain)+".json")
}

func prefixUsers(ca string) string {
	return path.Join(prefixCA(ca), "users")
}

// prefixUser gets the account folder for the user with email
func prefixUser(ca, email string) string {
	if email == "" {
		email = emptyEmail
	}
	return path.Join(prefixUsers(ca), safeKey(email))
}

// prefixUserReg gets the path to the registration file for the user with the
// given email address.
func prefixUserReg(ca, email string) string {
	return safeUserKey(ca, email, "registration", ".json")
}

// prefixUserKey gets the path to the private key file for the user with the
// given email address.
func prefixUserKey(ca, email string) string {
	return safeUserKey(ca, email, "private", ".key")
}

func prefixOCSPStaple(cert *Certificate, pemBundle []byte) string {
	var ocspFileName string
	if len(cert.Names) > 0 {
		firstName := safeKey(cert.Names[0])
		ocspFileName = firstName + "-"
	}
	ocspFileName += fastHash(pemBundle)
	return path.Join(prefixOCSP, ocspFileName)
}

// safeUserKey returns a key for the given email,
// with the default filename, and the filename
// ending in the given extension.
func safeUserKey(ca, email, defaultFilename, extension string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	filename := emailUsername(email)
	if filename == "" {
		filename = defaultFilename
	}
	filename = safeKey(filename)
	return path.Join(prefixUser(ca, email), filename+extension)
}

// emailUsername returns the username portion of an email address (part before
// '@') or the original input if it can't find the "@" symbol.
func emailUsername(email string) string {
	at := strings.Index(email, "@")
	if at == -1 {
		return email
	} else if at == 0 {
		return email[1:]
	}
	return email[:at]
}

// safeKey standardizes and sanitizes str for use in a file path.
func safeKey(str string) string {
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
var defaultFileStorage = FileStorage{Path: dataDir()}

// DefaultStorage is the default Storage implementation.
var DefaultStorage Storage = defaultFileStorage
