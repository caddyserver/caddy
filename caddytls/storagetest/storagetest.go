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

// Package storagetest provides utilities to assist in testing caddytls.Storage
// implementations.
package storagetest

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/mholt/caddy/caddytls"
)

// StorageTest is a test harness that contains tests to execute all exposed
// parts of a Storage implementation.
type StorageTest struct {
	// Storage is the implementation to use during tests. This must be
	// present.
	caddytls.Storage

	// PreTest, if present, is called before every test. Any error returned
	// is returned from the test and the test does not continue.
	PreTest func() error

	// PostTest, if present, is executed after every test via defer which
	// means it executes even on failure of the test (but not on failure of
	// PreTest).
	PostTest func()

	// AfterUserEmailStore, if present, is invoked during
	// TestMostRecentUserEmail after each storage just in case anything
	// needs to be mocked.
	AfterUserEmailStore func(email string) error
}

// TestFunc holds information about a test.
type TestFunc struct {
	// Name is the friendly name of the test.
	Name string

	// Fn is the function that is invoked for the test.
	Fn func() error
}

// runPreTest runs the PreTest function if present.
func (s *StorageTest) runPreTest() error {
	if s.PreTest != nil {
		return s.PreTest()
	}
	return nil
}

// runPostTest runs the PostTest function if present.
func (s *StorageTest) runPostTest() {
	if s.PostTest != nil {
		s.PostTest()
	}
}

// AllFuncs returns all test functions that are part of this harness.
func (s *StorageTest) AllFuncs() []TestFunc {
	return []TestFunc{
		{"TestSiteInfoExists", s.TestSiteExists},
		{"TestSite", s.TestSite},
		{"TestUser", s.TestUser},
		{"TestMostRecentUserEmail", s.TestMostRecentUserEmail},
	}
}

// Test executes the entire harness using the testing package. Failures are
// reported via T.Fatal. If eagerFail is true, the first failure causes all
// testing to stop immediately.
func (s *StorageTest) Test(t *testing.T, eagerFail bool) {
	if errs := s.TestAll(eagerFail); len(errs) > 0 {
		ifaces := make([]interface{}, len(errs))
		for i, err := range errs {
			ifaces[i] = err
		}
		t.Fatal(ifaces...)
	}
}

// TestAll executes the entire harness and returns the results as an array of
// errors. If eagerFail is true, the first failure causes all testing to stop
// immediately.
func (s *StorageTest) TestAll(eagerFail bool) (errs []error) {
	for _, fn := range s.AllFuncs() {
		if err := fn.Fn(); err != nil {
			errs = append(errs, fmt.Errorf("%v failed: %v", fn.Name, err))
			if eagerFail {
				return
			}
		}
	}
	return
}

var simpleSiteData = &caddytls.SiteData{
	Cert: []byte("foo"),
	Key:  []byte("bar"),
	Meta: []byte("baz"),
}
var simpleSiteDataAlt = &caddytls.SiteData{
	Cert: []byte("qux"),
	Key:  []byte("quux"),
	Meta: []byte("corge"),
}

// TestSiteExists tests Storage.SiteExists.
func (s *StorageTest) TestSiteExists() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()

	// Should not exist at first
	siteExists, err := s.SiteExists("example.com")
	if err != nil {
		return err
	}

	if siteExists {
		return errors.New("Site should not exist")
	}

	// Should exist after we store it
	if err := s.StoreSite("example.com", simpleSiteData); err != nil {
		return err
	}

	siteExists, err = s.SiteExists("example.com")
	if err != nil {
		return err
	}

	if !siteExists {
		return errors.New("Expected site to exist")
	}

	// Site should no longer exist after we delete it
	if err := s.DeleteSite("example.com"); err != nil {
		return err
	}

	siteExists, err = s.SiteExists("example.com")
	if err != nil {
		return err
	}

	if siteExists {
		return errors.New("Site should not exist after delete")
	}
	return nil
}

// TestSite tests Storage.LoadSite, Storage.StoreSite, and Storage.DeleteSite.
func (s *StorageTest) TestSite() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()

	// Should be a not-found error at first
	_, err := s.LoadSite("example.com")
	if _, ok := err.(caddytls.ErrNotExist); !ok {
		return fmt.Errorf("Expected caddytls.ErrNotExist from load, got %T: %v", err, err)
	}

	// Delete should also be a not-found error at first
	err = s.DeleteSite("example.com")
	if _, ok := err.(caddytls.ErrNotExist); !ok {
		return fmt.Errorf("Expected ErrNotExist from delete, got: %v", err)
	}

	// Should store successfully and then load just fine
	if err := s.StoreSite("example.com", simpleSiteData); err != nil {
		return err
	}
	if siteData, err := s.LoadSite("example.com"); err != nil {
		return err
	} else if !bytes.Equal(siteData.Cert, simpleSiteData.Cert) {
		return errors.New("Unexpected cert returned after store")
	} else if !bytes.Equal(siteData.Key, simpleSiteData.Key) {
		return errors.New("Unexpected key returned after store")
	} else if !bytes.Equal(siteData.Meta, simpleSiteData.Meta) {
		return errors.New("Unexpected meta returned after store")
	}

	// Overwrite should work just fine
	if err := s.StoreSite("example.com", simpleSiteDataAlt); err != nil {
		return err
	}
	if siteData, err := s.LoadSite("example.com"); err != nil {
		return err
	} else if !bytes.Equal(siteData.Cert, simpleSiteDataAlt.Cert) {
		return errors.New("Unexpected cert returned after overwrite")
	}

	// It should delete fine and then not be there
	if err := s.DeleteSite("example.com"); err != nil {
		return err
	}
	_, err = s.LoadSite("example.com")
	if _, ok := err.(caddytls.ErrNotExist); !ok {
		return fmt.Errorf("Expected caddytls.ErrNotExist after delete, got %T: %v", err, err)
	}

	return nil
}

var simpleUserData = &caddytls.UserData{
	Reg: []byte("foo"),
	Key: []byte("bar"),
}
var simpleUserDataAlt = &caddytls.UserData{
	Reg: []byte("baz"),
	Key: []byte("qux"),
}

// TestUser tests Storage.LoadUser and Storage.StoreUser.
func (s *StorageTest) TestUser() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()

	// Should be a not-found error at first
	_, err := s.LoadUser("foo@example.com")
	if _, ok := err.(caddytls.ErrNotExist); !ok {
		return fmt.Errorf("Expected caddytls.ErrNotExist from load, got %T: %v", err, err)
	}

	// Should store successfully and then load just fine
	if err := s.StoreUser("foo@example.com", simpleUserData); err != nil {
		return err
	}
	if userData, err := s.LoadUser("foo@example.com"); err != nil {
		return err
	} else if !bytes.Equal(userData.Reg, simpleUserData.Reg) {
		return errors.New("Unexpected reg returned after store")
	} else if !bytes.Equal(userData.Key, simpleUserData.Key) {
		return errors.New("Unexpected key returned after store")
	}

	// Overwrite should work just fine
	if err := s.StoreUser("foo@example.com", simpleUserDataAlt); err != nil {
		return err
	}
	if userData, err := s.LoadUser("foo@example.com"); err != nil {
		return err
	} else if !bytes.Equal(userData.Reg, simpleUserDataAlt.Reg) {
		return errors.New("Unexpected reg returned after overwrite")
	}

	return nil
}

// TestMostRecentUserEmail tests Storage.MostRecentUserEmail.
func (s *StorageTest) TestMostRecentUserEmail() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()

	// Should be empty on first run
	if e := s.MostRecentUserEmail(); e != "" {
		return fmt.Errorf("Expected empty most recent user on first run, got: %v", e)
	}

	// If we store user, then that one should be returned
	if err := s.StoreUser("foo1@example.com", simpleUserData); err != nil {
		return err
	}
	if s.AfterUserEmailStore != nil {
		s.AfterUserEmailStore("foo1@example.com")
	}
	if e := s.MostRecentUserEmail(); e != "foo1@example.com" {
		return fmt.Errorf("Unexpected most recent email after first store: %v", e)
	}

	// If we store another user, then that one should be returned
	if err := s.StoreUser("foo2@example.com", simpleUserDataAlt); err != nil {
		return err
	}
	if s.AfterUserEmailStore != nil {
		s.AfterUserEmailStore("foo2@example.com")
	}
	if e := s.MostRecentUserEmail(); e != "foo2@example.com" {
		return fmt.Errorf("Unexpected most recent email after user key: %v", e)
	}
	return nil
}
