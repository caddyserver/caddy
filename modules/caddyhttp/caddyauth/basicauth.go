// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyauth

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	weakrand "math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(HTTPBasicAuth{})

	weakrand.Seed(time.Now().UnixNano())
}

// HTTPBasicAuth facilitates HTTP basic authentication.
type HTTPBasicAuth struct {
	// The algorithm with which the passwords are hashed. Default: bcrypt
	HashRaw json.RawMessage `json:"hash,omitempty" caddy:"namespace=http.authentication.hashes inline_key=algorithm"`

	// The list of accounts to authenticate.
	AccountList []Account `json:"accounts,omitempty"`

	// The name of the realm. Default: restricted
	Realm string `json:"realm,omitempty"`

	// If non-nil, a mapping of plaintext passwords to their
	// hashes will be cached in memory (with random eviction).
	// This can greatly improve the performance of traffic-heavy
	// servers that use secure password hashing algorithms, with
	// the downside that plaintext passwords will be stored in
	// memory for a longer time (this should not be a problem
	// as long as your machine is not compromised, at which point
	// all bets are off, since basicauth necessitates plaintext
	// passwords being received over the wire anyway).
	HashCache *Cache `json:"hash_cache,omitempty"`

	Accounts map[string]Account `json:"-"`
	Hash     Comparer           `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (HTTPBasicAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.http_basic",
		New: func() caddy.Module { return new(HTTPBasicAuth) },
	}
}

// Provision provisions the HTTP basic auth provider.
func (hba *HTTPBasicAuth) Provision(ctx caddy.Context) error {
	if hba.HashRaw == nil {
		hba.HashRaw = json.RawMessage(`{"algorithm": "bcrypt"}`)
	}

	// load password hasher
	hasherIface, err := ctx.LoadModule(hba, "HashRaw")
	if err != nil {
		return fmt.Errorf("loading password hasher module: %v", err)
	}
	hba.Hash = hasherIface.(Comparer)

	if hba.Hash == nil {
		return fmt.Errorf("hash is required")
	}

	repl := caddy.NewReplacer()

	// load account list
	hba.Accounts = make(map[string]Account)
	for i, acct := range hba.AccountList {
		if _, ok := hba.Accounts[acct.Username]; ok {
			return fmt.Errorf("account %d: username is not unique: %s", i, acct.Username)
		}

		acct.Username = repl.ReplaceAll(acct.Username, "")
		acct.Password = repl.ReplaceAll(acct.Password, "")
		acct.Salt = repl.ReplaceAll(acct.Salt, "")

		if acct.Username == "" || acct.Password == "" {
			return fmt.Errorf("account %d: username and password are required", i)
		}

		acct.password, err = base64.StdEncoding.DecodeString(acct.Password)
		if err != nil {
			return fmt.Errorf("base64-decoding password: %v", err)
		}
		if acct.Salt != "" {
			acct.salt, err = base64.StdEncoding.DecodeString(acct.Salt)
			if err != nil {
				return fmt.Errorf("base64-decoding salt: %v", err)
			}
		}

		hba.Accounts[acct.Username] = acct
	}
	hba.AccountList = nil // allow GC to deallocate

	if hba.HashCache != nil {
		hba.HashCache.cache = make(map[string]bool)
		hba.HashCache.mu = new(sync.Mutex)
	}

	return nil
}

// Authenticate validates the user credentials in req and returns the user, if valid.
func (hba HTTPBasicAuth) Authenticate(w http.ResponseWriter, req *http.Request) (User, bool, error) {
	username, plaintextPasswordStr, ok := req.BasicAuth()
	if !ok {
		return hba.promptForCredentials(w, nil)
	}

	account, accountExists := hba.Accounts[username]
	// don't return early if account does not exist; we want
	// to try to avoid side-channels that leak existence

	same, err := hba.correctPassword(account, []byte(plaintextPasswordStr))
	if err != nil {
		return hba.promptForCredentials(w, err)
	}
	if !same || !accountExists {
		return hba.promptForCredentials(w, nil)
	}

	return User{ID: username}, true, nil
}

func (hba HTTPBasicAuth) correctPassword(account Account, plaintextPassword []byte) (bool, error) {
	compare := func() (bool, error) {
		return hba.Hash.Compare(account.password, plaintextPassword, account.salt)
	}

	// if no caching is enabled, simply return the result of hashing + comparing
	if hba.HashCache == nil {
		return compare()
	}

	// compute a cache key that is unique for these input parameters
	cacheKey := hex.EncodeToString(append(append(account.password, account.salt...), plaintextPassword...))

	// fast track: if the result of the input is already cached, use it
	hba.HashCache.mu.Lock()
	same, ok := hba.HashCache.cache[cacheKey]
	if ok {
		hba.HashCache.mu.Unlock()
		return same, nil
	}
	hba.HashCache.mu.Unlock()

	// slow track: do the expensive op, then add it to the cache
	same, err := compare()
	if err != nil {
		return false, err
	}
	hba.HashCache.mu.Lock()
	if len(hba.HashCache.cache) >= 1000 {
		hba.HashCache.makeRoom() // keep cache size under control
	}
	hba.HashCache.cache[cacheKey] = same
	hba.HashCache.mu.Unlock()

	return same, nil
}

func (hba HTTPBasicAuth) promptForCredentials(w http.ResponseWriter, err error) (User, bool, error) {
	// browsers show a message that says something like:
	// "The website says: <realm>"
	// which is kinda dumb, but whatever.
	realm := hba.Realm
	if realm == "" {
		realm = "restricted"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	return User{}, false, err
}

// Cache enables caching of basic auth results. This is especially
// helpful for secure password hashes which can be expensive to
// compute on every HTTP request.
type Cache struct {
	mu *sync.Mutex

	// map of concatenated hashed password + plaintext password + salt, to result
	cache map[string]bool
}

// makeRoom deletes about 1/10 of the items in the cache
// in order to keep its size under control. It must not be
// called without a lock on c.mu.
func (c *Cache) makeRoom() {
	// we delete more than just 1 entry so that we don't have
	// to do this on every request; assuming the capacity of
	// the cache is on a long tail, we can save a lot of CPU
	// time by doing a whole bunch of deletions now and then
	// we won't have to do them again for a while
	numToDelete := len(c.cache) / 10
	if numToDelete < 1 {
		numToDelete = 1
	}
	for deleted := 0; deleted <= numToDelete; deleted++ {
		// Go maps are "nondeterministic" not actually random,
		// so although we could just chop off the "front" of the
		// map with less code, this is a heavily skewed eviction
		// strategy; generating random numbers is cheap and
		// ensures a much better distribution.
		rnd := weakrand.Intn(len(c.cache))
		i := 0
		for key := range c.cache {
			if i == rnd {
				delete(c.cache, key)
				break
			}
			i++
		}
	}
}

// Comparer is a type that can securely compare
// a plaintext password with a hashed password
// in constant-time. Comparers should hash the
// plaintext password and then use constant-time
// comparison.
type Comparer interface {
	// Compare returns true if the result of hashing
	// plaintextPassword with salt is hashedPassword,
	// false otherwise. An error is returned only if
	// there is a technical/configuration error.
	Compare(hashedPassword, plaintextPassword, salt []byte) (bool, error)
}

// Account contains a username, password, and salt (if applicable).
type Account struct {
	// A user's username.
	Username string `json:"username"`

	// The user's hashed password, base64-encoded.
	Password string `json:"password"`

	// The user's password salt, base64-encoded; for
	// algorithms where external salt is needed.
	Salt string `json:"salt,omitempty"`

	password, salt []byte
}

// Interface guards
var (
	_ caddy.Provisioner = (*HTTPBasicAuth)(nil)
	_ Authenticator     = (*HTTPBasicAuth)(nil)
)
