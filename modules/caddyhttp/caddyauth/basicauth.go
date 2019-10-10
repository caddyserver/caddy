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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(HTTPBasicAuth{})
}

// HTTPBasicAuth facilitates HTTP basic authentication.
type HTTPBasicAuth struct {
	HashRaw     json.RawMessage `json:"hash,omitempty"`
	AccountList []Account       `json:"accounts,omitempty"`
	Realm       string          `json:"realm,omitempty"`

	Accounts map[string]Account `json:"-"`
	Hash     Comparer           `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (HTTPBasicAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.authentication.providers.http_basic",
		New:  func() caddy.Module { return new(HTTPBasicAuth) },
	}
}

// Provision provisions the HTTP basic auth provider.
func (hba *HTTPBasicAuth) Provision(ctx caddy.Context) error {
	if hba.HashRaw == nil {
		return fmt.Errorf("passwords must be hashed, so a hash must be defined")
	}

	// load password hasher
	hashIface, err := ctx.LoadModuleInline("algorithm", "http.handlers.authentication.hashes", hba.HashRaw)
	if err != nil {
		return fmt.Errorf("loading password hasher module: %v", err)
	}
	hba.Hash = hashIface.(Comparer)
	hba.HashRaw = nil // allow GC to deallocate

	if hba.Hash == nil {
		return fmt.Errorf("hash is required")
	}

	// load account list
	hba.Accounts = make(map[string]Account)
	for _, acct := range hba.AccountList {
		if _, ok := hba.Accounts[acct.Username]; ok {
			return fmt.Errorf("username is not unique: %s", acct.Username)
		}
		hba.Accounts[acct.Username] = acct
	}
	hba.AccountList = nil // allow GC to deallocate

	return nil
}

// Authenticate validates the user credentials in req and returns the user, if valid.
func (hba HTTPBasicAuth) Authenticate(w http.ResponseWriter, req *http.Request) (User, bool, error) {
	username, plaintextPasswordStr, ok := req.BasicAuth()

	// if basic auth is missing or invalid, prompt for credentials
	if !ok {
		// browsers show a message that says something like:
		// "The website says: <realm>"
		// which is kinda dumb, but whatever.
		realm := hba.Realm
		if realm == "" {
			realm = "restricted"
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))

		return User{}, false, nil
	}

	plaintextPassword := []byte(plaintextPasswordStr)

	account, accountExists := hba.Accounts[username]
	// don't return early if account does not exist; we want
	// to try to avoid side-channels that leak existence

	same, err := hba.Hash.Compare(account.Password, plaintextPassword, account.Salt)
	if err != nil {
		return User{}, false, err
	}
	if !same || !accountExists {
		return User{}, false, nil
	}

	return User{ID: username}, true, nil
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

type quickComparer struct{}

func (quickComparer) Compare(theirHash, plaintext, _ []byte) (bool, error) {
	ourHash := quickHash(plaintext)
	return hashesMatch(ourHash, theirHash), nil
}

func hashesMatch(pwdHash1, pwdHash2 []byte) bool {
	return subtle.ConstantTimeCompare(pwdHash1, pwdHash2) == 1
}

// quickHash returns the SHA-256 of v. It
// is not secure for password storage, but
// it is useful for efficiently normalizing
// the length of plaintext passwords for
// constant-time comparisons.
//
// Errors are discarded.
func quickHash(v []byte) []byte {
	h := sha256.New()
	h.Write([]byte(v))
	return h.Sum(nil)
}

// Account contains a username, password, and salt (if applicable).
type Account struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
	Salt     []byte `json:"salt,omitempty"` // for algorithms where external salt is needed
}

// Interface guards
var (
	_ caddy.Provisioner = (*HTTPBasicAuth)(nil)
	_ Authenticator     = (*HTTPBasicAuth)(nil)
)
