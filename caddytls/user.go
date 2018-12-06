// Copyright 2015 Light Code Labs, LLC
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

package caddytls

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xenolf/lego/acme"
)

// User represents a Let's Encrypt user account.
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

// GetEmail gets u's email.
func (u User) GetEmail() string {
	return u.Email
}

// GetRegistration gets u's registration resource.
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

// GetPrivateKey gets u's private key.
func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// newUser creates a new User for the given email address
// with a new private key. This function does NOT save the
// user to disk or register it via ACME. If you want to use
// a user account that might already exist, call getUser
// instead. It does NOT prompt the user.
func newUser(email string) (User, error) {
	user := User{Email: email}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return user, errors.New("error generating private key: " + err.Error())
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
func getEmail(cfg *Config, userPresent bool) (string, error) {
	storage, err := cfg.StorageFor(cfg.CAUrl)
	if err != nil {
		return "", err
	}

	// First try memory (command line flag or typed by user previously)
	leEmail := DefaultEmail

	// Then try to get most recent user email from storage
	if leEmail == "" {
		leEmail = storage.MostRecentUserEmail()
		DefaultEmail = leEmail // save for next time
	}

	// Looks like there is no email address readily available,
	// so we will have to ask the user if we can.
	if leEmail == "" && userPresent {
		// evidently, no User data was present in storage;
		// thus we must make a new User so that we can get
		// the Terms of Service URL via our ACME client, phew!
		user, err := newUser("")
		if err != nil {
			return "", err
		}

		// get the agreement URL
		agreementURL := agreementTestURL
		if agreementURL == "" {
			// we call acme.NewClient directly because newACMEClient
			// would require that we already know the user's email
			caURL := DefaultCAUrl
			if cfg.CAUrl != "" {
				caURL = cfg.CAUrl
			}
			tempClient, err := acme.NewClient(caURL, user, "")
			if err != nil {
				return "", fmt.Errorf("making ACME client to get ToS URL: %v", err)
			}
			agreementURL = tempClient.GetToSURL()
		}

		// prompt the user for an email address and terms agreement
		reader := bufio.NewReader(stdin)
		promptUserAgreement(agreementURL)
		fmt.Println("Please enter your email address to signify agreement and to be notified")
		fmt.Println("in case of issues. You can leave it blank, but we don't recommend it.")
		fmt.Print("  Email address: ")
		leEmail, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("reading email address: %v", err)
		}
		leEmail = strings.TrimSpace(leEmail)
		DefaultEmail = leEmail
		Agreed = true

		// save the new user to preserve this for next time
		user.Email = leEmail
		err = saveUser(storage, user)
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
func getUser(storage Storage, email string) (User, error) {
	var user User

	// open user reg
	userData, err := storage.LoadUser(email)
	if err != nil {
		if _, ok := err.(ErrNotExist); ok {
			// create a new user
			return newUser(email)
		}
		return user, err
	}

	// load user information
	err = json.Unmarshal(userData.Reg, &user)
	if err != nil {
		return user, err
	}

	// load their private key
	user.key, err = loadPrivateKey(userData.Key)
	return user, err
}

// saveUser persists a user's key and account registration
// to the file system. It does NOT register the user via ACME
// or prompt the user. You must also pass in the storage
// wherein the user should be saved. It should be the storage
// for the CA with which user has an account.
func saveUser(storage Storage, user User) error {
	// Save the private key and registration
	userData := new(UserData)
	var err error
	userData.Key, err = savePrivateKey(user.key)
	if err == nil {
		userData.Reg, err = json.MarshalIndent(&user, "", "\t")
	}
	if err == nil {
		err = storage.StoreUser(user.Email, userData)
	}
	return err
}

// promptUserAgreement simply outputs the standard user
// agreement prompt with the given agreement URL.
// It outputs a newline after the message.
func promptUserAgreement(agreementURL string) {
	const userAgreementPrompt = `Your sites will be served over HTTPS automatically using Let's Encrypt.
By continuing, you agree to the Let's Encrypt Subscriber Agreement at:`
	fmt.Printf("\n\n%s\n  %s\n", userAgreementPrompt, agreementURL)
}

// askUserAgreement prompts the user to agree to the agreement
// at the given agreement URL via stdin. It returns whether the
// user agreed or not.
func askUserAgreement(agreementURL string) bool {
	promptUserAgreement(agreementURL)
	fmt.Print("Do you agree to the terms? (y/n): ")

	reader := bufio.NewReader(stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes"
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
