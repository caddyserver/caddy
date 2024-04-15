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
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(HTTPBasicAuth{})
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
	// passwords being received over the wire anyway). Note that
	// a cache hit does not mean it is a valid password.
	HashCache *Cache `json:"hash_cache,omitempty"`

	Accounts map[string]Account `json:"-"`
	Hash     Comparer           `json:"-"`

	// fakePassword is used when a given user is not found,
	// so that timing side-channels can be mitigated: it gives
	// us something to hash and compare even if the user does
	// not exist, which should have similar timing as a user
	// account that does exist.
	fakePassword []byte
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

	// if supported, generate a fake password we can compare against if needed
	if hasher, ok := hba.Hash.(Hasher); ok {
		hba.fakePassword = hasher.FakeHash()
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

		if acct.Username == "" || acct.Password == "" {
			return fmt.Errorf("account %d: username and password are required", i)
		}

		// TODO: Remove support for redundantly-encoded b64-encoded hashes
		// Passwords starting with '$' are likely in Modular Crypt Format,
		// so we don't need to base64 decode them. But historically, we
		// required redundant base64, so we try to decode it otherwise.
		if strings.HasPrefix(acct.Password, "$") {
			acct.password = []byte(acct.Password)
		} else {
			acct.password, err = base64.StdEncoding.DecodeString(acct.Password)
			if err != nil {
				return fmt.Errorf("base64-decoding password: %v", err)
			}
		}

		hba.Accounts[acct.Username] = acct
	}
	hba.AccountList = nil // allow GC to deallocate

	if hba.HashCache != nil {
		hba.HashCache.cache = make(map[string]bool)
		hba.HashCache.mu = new(sync.RWMutex)
		hba.HashCache.g = new(singleflight.Group)
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
	if !accountExists {
		// don't return early if account does not exist; we want
		// to try to avoid side-channels that leak existence, so
		// we use a fake password to simulate realistic CPU cycles
		account.password = hba.fakePassword
	}

	same, err := hba.correctPassword(account, []byte(plaintextPasswordStr))
	if err != nil || !same || !accountExists {
		return hba.promptForCredentials(w, err)
	}

	return User{ID: username}, true, nil
}

func (hba HTTPBasicAuth) correctPassword(account Account, plaintextPassword []byte) (bool, error) {
	compare := func() (bool, error) {
		return hba.Hash.Compare(account.password, plaintextPassword)
	}

	// if no caching is enabled, simply return the result of hashing + comparing
	if hba.HashCache == nil {
		return compare()
	}

	// compute a cache key that is unique for these input parameters
	cacheKey := hex.EncodeToString(append(account.password, plaintextPassword...))

	// fast track: if the result of the input is already cached, use it
	hba.HashCache.mu.RLock()
	same, ok := hba.HashCache.cache[cacheKey]
	hba.HashCache.mu.RUnlock()
	if ok {
		return same, nil
	}
	// slow track: do the expensive op, then add it to the cache
	// but perform it in a singleflight group so that multiple
	// parallel requests using the same password don't cause a
	// thundering herd problem by all performing the same hashing
	// operation before the first one finishes and caches it.
	v, err, _ := hba.HashCache.g.Do(cacheKey, func() (any, error) {
		return compare()
	})
	if err != nil {
		return false, err
	}
	same = v.(bool)
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
	mu *sync.RWMutex
	g  *singleflight.Group

	// map of concatenated hashed password + plaintext password, to result
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
		//nolint:gosec
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
	// plaintextPassword is hashedPassword, false
	// otherwise. An error is returned only if
	// there is a technical/configuration error.
	Compare(hashedPassword, plaintextPassword []byte) (bool, error)
}

// Hasher is a type that can generate a secure hash
// given a plaintext. Hashing modules which implement
// this interface can be used with the hash-password
// subcommand as well as benefitting from anti-timing
// features. A hasher also returns a fake hash which
// can be used for timing side-channel mitigation.
type Hasher interface {
	Hash(plaintext []byte) ([]byte, error)
	FakeHash() []byte
}

// Account contains a username and password.
type Account struct {
	// A user's username.
	Username string `json:"username"`

	// The user's hashed password, in Modular Crypt Format (with `$` prefix)
	// or base64-encoded.
	Password string `json:"password"`

	password []byte
}

// Interface guards
var (
	_ caddy.Provisioner = (*HTTPBasicAuth)(nil)
	_ Authenticator     = (*HTTPBasicAuth)(nil)
)
