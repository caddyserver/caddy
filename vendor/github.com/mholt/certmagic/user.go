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
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/xenolf/lego/lego"
	"github.com/xenolf/lego/registration"
)

// user represents a Let's Encrypt user account.
type user struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// GetEmail gets u's email.
func (u user) GetEmail() string {
	return u.Email
}

// GetRegistration gets u's registration resource.
func (u user) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey gets u's private key.
func (u user) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// newUser creates a new User for the given email address
// with a new private key. This function does NOT save the
// user to disk or register it via ACME. If you want to use
// a user account that might already exist, call getUser
// instead. It does NOT prompt the user.
func (cfg *Config) newUser(email string) (user, error) {
	user := user{Email: email}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return user, fmt.Errorf("generating private key: %v", err)
	}
	user.key = privateKey
	return user, nil
}

// getEmail does everything it can to obtain an email address
// from the user within the scope of memory and storage to use
// for ACME TLS. If it cannot get an email address, it returns
// empty string. (If user is present, it will warn the user of
// the consequences of an empty email.) This function MAY prompt
// the user for input. If userPresent is false, the operator
// will NOT be prompted and an empty email may be returned.
// If the user is prompted, a new User will be created and
// stored in storage according to the email address they
// provided (which might be blank).
func (cfg *Config) getEmail(userPresent bool) (string, error) {
	// First try memory
	leEmail := cfg.Email
	if leEmail == "" {
		leEmail = Email
	}

	// Then try to get most recent user email from storage
	if leEmail == "" {
		leEmail = cfg.mostRecentUserEmail()
		cfg.Email = leEmail // save for next time
	}

	// Looks like there is no email address readily available,
	// so we will have to ask the user if we can.
	if leEmail == "" && userPresent {
		// evidently, no User data was present in storage;
		// thus we must make a new User so that we can get
		// the Terms of Service URL via our ACME client, phew!
		user, err := cfg.newUser("")
		if err != nil {
			return "", err
		}

		// get the agreement URL
		agreementURL := agreementTestURL
		if agreementURL == "" {
			// we call acme.NewClient directly because newACMEClient
			// would require that we already know the user's email
			caURL := CA
			if cfg.CA != "" {
				caURL = cfg.CA
			}
			legoConfig := lego.NewConfig(user)
			legoConfig.CADirURL = caURL
			legoConfig.UserAgent = UserAgent
			tempClient, err := lego.NewClient(legoConfig)
			if err != nil {
				return "", fmt.Errorf("making ACME client to get ToS URL: %v", err)
			}
			agreementURL = tempClient.GetToSURL()
		}

		// prompt the user for an email address and terms agreement
		reader := bufio.NewReader(stdin)
		cfg.promptUserAgreement(agreementURL)
		fmt.Println("Please enter your email address to signify agreement and to be notified")
		fmt.Println("in case of issues. You can leave it blank, but we don't recommend it.")
		fmt.Print("  Email address: ")
		leEmail, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("reading email address: %v", err)
		}
		leEmail = strings.TrimSpace(leEmail)
		cfg.Email = leEmail
		cfg.Agreed = true

		// save the new user to preserve this for next time
		user.Email = leEmail
		err = cfg.saveUser(user)
		if err != nil {
			return "", err
		}
	}

	// lower-casing the email is important for consistency
	return strings.ToLower(leEmail), nil
}

// getUser loads the user with the given email from disk
// using the provided storage. If the user does not exist,
// it will create a new one, but it does NOT save new
// users to the disk or register them via ACME. It does
// NOT prompt the user.
func (cfg *Config) getUser(email string) (user, error) {
	var user user

	regBytes, err := cfg.certCache.storage.Load(StorageKeys.UserReg(cfg.CA, email))
	if err != nil {
		if _, ok := err.(ErrNotExist); ok {
			// create a new user
			return cfg.newUser(email)
		}
		return user, err
	}
	keyBytes, err := cfg.certCache.storage.Load(StorageKeys.UserPrivateKey(cfg.CA, email))
	if err != nil {
		if _, ok := err.(ErrNotExist); ok {
			// create a new user
			return cfg.newUser(email)
		}
		return user, err
	}

	err = json.Unmarshal(regBytes, &user)
	if err != nil {
		return user, err
	}
	user.key, err = decodePrivateKey(keyBytes)
	return user, err
}

// saveUser persists a user's key and account registration
// to the file system. It does NOT register the user via ACME
// or prompt the user. You must also pass in the storage
// wherein the user should be saved. It should be the storage
// for the CA with which user has an account.
func (cfg *Config) saveUser(user user) error {
	regBytes, err := json.MarshalIndent(&user, "", "\t")
	if err != nil {
		return err
	}
	keyBytes, err := encodePrivateKey(user.key)
	if err != nil {
		return err
	}

	all := []keyValue{
		{
			key:   StorageKeys.UserReg(cfg.CA, user.Email),
			value: regBytes,
		},
		{
			key:   StorageKeys.UserPrivateKey(cfg.CA, user.Email),
			value: keyBytes,
		},
	}

	return storeTx(cfg.certCache.storage, all)
}

// promptUserAgreement simply outputs the standard user
// agreement prompt with the given agreement URL.
// It outputs a newline after the message.
func (cfg *Config) promptUserAgreement(agreementURL string) {
	const userAgreementPrompt = `Your sites will be served over HTTPS automatically using Let's Encrypt.
By continuing, you agree to the Let's Encrypt Subscriber Agreement at:`
	fmt.Printf("\n\n%s\n  %s\n", userAgreementPrompt, agreementURL)
}

// askUserAgreement prompts the user to agree to the agreement
// at the given agreement URL via stdin. It returns whether the
// user agreed or not.
func (cfg *Config) askUserAgreement(agreementURL string) bool {
	cfg.promptUserAgreement(agreementURL)
	fmt.Print("Do you agree to the terms? (y/n): ")

	reader := bufio.NewReader(stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes"
}

// mostRecentUserEmail finds the most recently-written user file
// in s. Since this is part of a complex sequence to get a user
// account, errors here are discarded to simplify code flow in
// the caller, and errors are not important here anyway.
func (cfg *Config) mostRecentUserEmail() string {
	userList, err := cfg.certCache.storage.List(StorageKeys.UsersPrefix(cfg.CA))
	if err != nil || len(userList) == 0 {
		return ""
	}
	sort.Slice(userList, func(i, j int) bool {
		iInfo, _ := cfg.certCache.storage.Stat(StorageKeys.UserPrefix(cfg.CA, userList[i]))
		jInfo, _ := cfg.certCache.storage.Stat(StorageKeys.UserPrefix(cfg.CA, userList[j]))
		return jInfo.Modified.Before(iInfo.Modified)
	})
	user, err := cfg.getUser(userList[0])
	if err != nil {
		return ""
	}
	return user.Email
}

// agreementTestURL is set during tests to skip requiring
// setting up an entire ACME CA endpoint.
var agreementTestURL string

// stdin is used to read the user's input if prompted;
// this is changed by tests during tests.
var stdin = io.ReadWriter(os.Stdin)

// The name of the folder for accounts where the email
// address was not provided; default 'username' if you will,
// but only for local/storage use, not with the CA.
const emptyEmail = "default"
