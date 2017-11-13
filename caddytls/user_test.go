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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"os"

	"github.com/xenolf/lego/acme"
)

func TestUser(t *testing.T) {
	defer testStorage.clean()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Could not generate test private key: %v", err)
	}
	u := User{
		Email:        "me@mine.com",
		Registration: new(acme.RegistrationResource),
		key:          privateKey,
	}

	if expected, actual := "me@mine.com", u.GetEmail(); actual != expected {
		t.Errorf("Expected email '%s' but got '%s'", expected, actual)
	}
	if u.GetRegistration() == nil {
		t.Error("Expected a registration resource, but got nil")
	}
	if expected, actual := privateKey, u.GetPrivateKey(); actual != expected {
		t.Errorf("Expected the private key at address %p but got one at %p instead ", expected, actual)
	}
}

func TestNewUser(t *testing.T) {
	email := "me@foobar.com"
	user, err := newUser(email)
	if err != nil {
		t.Fatalf("Error creating user: %v", err)
	}
	if user.key == nil {
		t.Error("Private key is nil")
	}
	if user.Email != email {
		t.Errorf("Expected email to be %s, but was %s", email, user.Email)
	}
	if user.Registration != nil {
		t.Error("New user already has a registration resource; it shouldn't")
	}
}

func TestSaveUser(t *testing.T) {
	defer testStorage.clean()

	email := "me@foobar.com"
	user, err := newUser(email)
	if err != nil {
		t.Fatalf("Error creating user: %v", err)
	}

	err = saveUser(testStorage, user)
	if err != nil {
		t.Fatalf("Error saving user: %v", err)
	}
	_, err = testStorage.LoadUser(email)
	if err != nil {
		t.Errorf("Cannot access user data, error: %v", err)
	}
}

func TestGetUserDoesNotAlreadyExist(t *testing.T) {
	defer testStorage.clean()

	user, err := getUser(testStorage, "user_does_not_exist@foobar.com")
	if err != nil {
		t.Fatalf("Error getting user: %v", err)
	}

	if user.key == nil {
		t.Error("Expected user to have a private key, but it was nil")
	}
}

func TestGetUserAlreadyExists(t *testing.T) {
	defer testStorage.clean()

	email := "me@foobar.com"

	// Set up test
	user, err := newUser(email)
	if err != nil {
		t.Fatalf("Error creating user: %v", err)
	}
	err = saveUser(testStorage, user)
	if err != nil {
		t.Fatalf("Error saving user: %v", err)
	}

	// Expect to load user from disk
	user2, err := getUser(testStorage, email)
	if err != nil {
		t.Fatalf("Error getting user: %v", err)
	}

	// Assert keys are the same
	if !PrivateKeysSame(user.key, user2.key) {
		t.Error("Expected private key to be the same after loading, but it wasn't")
	}

	// Assert emails are the same
	if user.Email != user2.Email {
		t.Errorf("Expected emails to be equal, but was '%s' before and '%s' after loading", user.Email, user2.Email)
	}
}

func TestGetEmail(t *testing.T) {
	storageBasePath = testStorage.Path // to contain calls that create a new Storage...

	// let's not clutter up the output
	origStdout := os.Stdout
	os.Stdout = nil
	defer func() { os.Stdout = origStdout }()

	defer testStorage.clean()
	DefaultEmail = "test2@foo.com"

	// Test1: Use default email from flag (or user previously typing it)
	actual := getEmail(testStorage, true)
	if actual != DefaultEmail {
		t.Errorf("Did not get correct email from memory; expected '%s' but got '%s'", DefaultEmail, actual)
	}

	// Test2: Get input from user
	DefaultEmail = ""
	stdin = new(bytes.Buffer)
	_, err := io.Copy(stdin, strings.NewReader("test3@foo.com\n"))
	if err != nil {
		t.Fatalf("Could not simulate user input, error: %v", err)
	}
	actual = getEmail(testStorage, true)
	if actual != "test3@foo.com" {
		t.Errorf("Did not get correct email from user input prompt; expected '%s' but got '%s'", "test3@foo.com", actual)
	}

	// Test3: Get most recent email from before
	DefaultEmail = ""
	for i, eml := range []string{
		"TEST4-3@foo.com", // test case insensitivity
		"test4-2@foo.com",
		"test4-1@foo.com",
	} {
		u, err := newUser(eml)
		if err != nil {
			t.Fatalf("Error creating user %d: %v", i, err)
		}
		err = saveUser(testStorage, u)
		if err != nil {
			t.Fatalf("Error saving user %d: %v", i, err)
		}

		// Change modified time so they're all different and the test becomes more deterministic
		f, err := os.Stat(testStorage.user(eml))
		if err != nil {
			t.Fatalf("Could not access user folder for '%s': %v", eml, err)
		}
		chTime := f.ModTime().Add(-(time.Duration(i) * time.Hour)) // 1 second isn't always enough space!
		if err := os.Chtimes(testStorage.user(eml), chTime, chTime); err != nil {
			t.Fatalf("Could not change user folder mod time for '%s': %v", eml, err)
		}
	}
	actual = getEmail(testStorage, true)
	if actual != "test4-3@foo.com" {
		t.Errorf("Did not get correct email from storage; expected '%s' but got '%s'", "test4-3@foo.com", actual)
	}
}

var testStorage = &FileStorage{Path: "./testdata"}

func (s *FileStorage) clean() error {
	return os.RemoveAll(s.Path)
}
