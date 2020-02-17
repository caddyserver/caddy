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
	// The algorithm with which the passwords are hashed. Default: bcrypt
	HashRaw json.RawMessage `json:"hash,omitempty" caddy:"namespace=http.authentication.hashes inline_key=algorithm"`

	// The list of accounts to authenticate.
	AccountList []Account `json:"accounts,omitempty"`

	// The name of the realm. Default: restricted
	Realm string `json:"realm,omitempty"`

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
		acct.Password = repl.ReplaceAll(string(acct.Password), "")
		acct.Salt = repl.ReplaceAll(string(acct.Salt), "")

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

	same, err := hba.Hash.Compare(account.password, plaintextPassword, account.salt)
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
