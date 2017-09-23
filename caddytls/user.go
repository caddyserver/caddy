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

// getEmail does everything it can to obtain an email
// address from the user within the scope of storage
// to use for ACME TLS. If it cannot get an email
// address, it returns empty string. (It will warn the
// user of the consequences of an empty email.) This
// function MAY prompt the user for input. If userPresent
// is false, the operator will NOT be prompted and an
// empty email may be returned.
func getEmail(storage Storage, userPresent bool) string {
	// First try memory (command line flag or typed by user previously)
	leEmail := DefaultEmail
	if leEmail == "" {
		// Then try to get most recent user email
		leEmail = storage.MostRecentUserEmail()
		// Save for next time
		DefaultEmail = leEmail
	}
	if leEmail == "" && userPresent {
		// Alas, we must bother the user and ask for an email address;
		// if they proceed they also agree to the SA.
		reader := bufio.NewReader(stdin)
		fmt.Println("\nYour sites will be served over HTTPS automatically using Let's Encrypt.")
		fmt.Println("By continuing, you agree to the Let's Encrypt Subscriber Agreement at:")
		fmt.Println("  " + saURL) // TODO: Show current SA link
		fmt.Println("Please enter your email address so you can recover your account if needed.")
		fmt.Println("You can leave it blank, but you'll lose the ability to recover your account.")
		fmt.Print("Email address: ")
		var err error
		leEmail, err = reader.ReadString('\n')
		if err != nil {
			return ""
		}
		leEmail = strings.TrimSpace(leEmail)
		DefaultEmail = leEmail
		Agreed = true
	}
	return strings.ToLower(leEmail)
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

// promptUserAgreement prompts the user to agree to the agreement
// at agreementURL via stdin. If the agreement has changed, then pass
// true as the second argument. If this is the user's first time
// agreeing, pass false. It returns whether the user agreed or not.
func promptUserAgreement(agreementURL string, changed bool) bool {
	if changed {
		fmt.Printf("The Let's Encrypt Subscriber Agreement has changed:\n  %s\n", agreementURL)
		fmt.Print("Do you agree to the new terms? (y/n): ")
	} else {
		fmt.Printf("To continue, you must agree to the Let's Encrypt Subscriber Agreement:\n  %s\n", agreementURL)
		fmt.Print("Do you agree to the terms? (y/n): ")
	}

	reader := bufio.NewReader(stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes"
}

// stdin is used to read the user's input if prompted;
// this is changed by tests during tests.
var stdin = io.ReadWriter(os.Stdin)

// The name of the folder for accounts where the email
// address was not provided; default 'username' if you will.
const emptyEmail = "default"

// TODO: After Boulder implements the 'meta' field of the directory,
// we can get this link dynamically.
const saURL = "https://acme-v01.api.letsencrypt.org/terms"
