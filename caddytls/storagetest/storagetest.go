// Package storagetest provides utilities to assist in testing caddytls.Storage
// implementations.
package storagetest

import (
	"errors"
	"fmt"
	"github.com/mholt/caddy/caddytls"
	"testing"
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
		{"TestSiteInfoExists", s.TestSiteInfoExists},
		{"TestSiteInfoExistsNoCert", s.TestSiteInfoExistsNoCert},
		{"TestSiteCert", s.TestSiteCert},
		{"TestSiteKey", s.TestSiteKey},
		{"TestSiteMeta", s.TestSiteMeta},
		{"TestUserReg", s.TestUserReg},
		{"TestUserKey", s.TestUserKey},
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

// TestSiteInfoExists tests Storage.SiteInfoExists.
func (s *StorageTest) TestSiteInfoExists() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()

	// Should not exist at first
	if s.SiteInfoExists("example.com") {
		return errors.New("Site should not exist")
	}

	// Still should not exist even if we just put the cert there
	if err := s.StoreSiteCert("example.com", []byte("foo")); err != nil {
		return err
	}
	if s.SiteInfoExists("example.com") {
		return errors.New("Site should not exist with just cert")
	}

	// Should exist after we put the key there
	if err := s.StoreSiteKey("example.com", []byte("foo")); err != nil {
		return err
	}
	if !s.SiteInfoExists("example.com") {
		return errors.New("Expected site to exist")
	}

	// Site should no longer exist after we delete it
	if err := s.DeleteSiteCert("example.com"); err != nil {
		return err
	}
	if s.SiteInfoExists("example.com") {
		return errors.New("Site should not exist after delete")
	}
	return nil
}

// TestSiteInfoExistsNoCert tests Storage.SiteInfoExists when a cert is not
// present.
func (s *StorageTest) TestSiteInfoExistsNoCert() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()

	// Had to be separated from TestSiteInfoExists because this tests
	// setting a key first without setting a cert
	if err := s.StoreSiteKey("example.com", []byte("foo")); err != nil {
		return err
	}
	if s.SiteInfoExists("example.com") {
		return errors.New("Site should not exist with just key")
	}
	return nil
}

// loadFunc represents byte array loader.
type loadFunc func(string) ([]byte, error)

// storeFunc represents byte array persister.
type storeFunc func(string, []byte) error

// deleteFunc represents byte array deleter.
type deleteFunc func(string) error

// testLoadAndStore tests load, store, and delete functions of the storage. All
// parameters must be non-nil except for deleteFn which can be nil.
func testLoadAndStore(key string, loadFn loadFunc, storeFn storeFunc, deleteFn deleteFunc) error {
	// Should be a not-found error at first
	if _, err := loadFn(key); err != caddytls.ErrStorageNotFound {
		return fmt.Errorf("Expected ErrStorageNotFound from load, got: %v", err)
	}

	// If there is a delete, it should also be a not-found error at first
	if deleteFn != nil {
		if err := deleteFn(key); err != caddytls.ErrStorageNotFound {
			return fmt.Errorf("Expected ErrStorageNotFound from delete, got: %v", err)
		}
	}

	// Should store successfully and then load just fine
	if err := storeFn(key, []byte("foo")); err != nil {
		return err
	}
	if byts, err := loadFn(key); err != nil {
		return err
	} else if string(byts) != "foo" {
		return errors.New("Unexpected bytes returned after store")
	}

	// Overwrite should work just fine
	if err := storeFn(key, []byte("bar")); err != nil {
		return err
	}
	if byts, err := loadFn(key); err != nil {
		return err
	} else if string(byts) != "bar" {
		return errors.New("Unexpected bytes returned after overwrite")
	}

	// If there is a delete, it should delete fine and then not be there
	if deleteFn != nil {
		if err := deleteFn(key); err != nil {
			return err
		}
		if _, err := loadFn(key); err != caddytls.ErrStorageNotFound {
			return fmt.Errorf("Expected ErrStorageNotFound after delete, got: %v", err)
		}
	}

	return nil
}

// TestSiteCert tests Storage.*SiteCert.
func (s *StorageTest) TestSiteCert() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()
	return testLoadAndStore("example.com", s.LoadSiteCert, s.StoreSiteCert, s.DeleteSiteCert)
}

// TestSiteKey tests Storage.*SiteKey.
func (s *StorageTest) TestSiteKey() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()
	return testLoadAndStore("example.com", s.LoadSiteKey, s.StoreSiteKey, nil)
}

// TestSiteMeta tests Storage.*SiteMeta.
func (s *StorageTest) TestSiteMeta() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()
	return testLoadAndStore("example.com", s.LoadSiteMeta, s.StoreSiteMeta, nil)
}

// TestUserReg tests Storage.*UserReg.
func (s *StorageTest) TestUserReg() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()
	return testLoadAndStore("foo@example.com", s.LoadUserReg, s.StoreUserReg, nil)
}

// TestUserKey tests Storage.*UserKey.
func (s *StorageTest) TestUserKey() error {
	if err := s.runPreTest(); err != nil {
		return err
	}
	defer s.runPostTest()
	return testLoadAndStore("foo@example.com", s.LoadUserKey, s.StoreUserKey, nil)
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

	// If we store user reg, then that one should be returned
	if err := s.StoreUserReg("foo1@example.com", []byte("foo")); err != nil {
		return err
	}
	if s.AfterUserEmailStore != nil {
		s.AfterUserEmailStore("foo1@example.com")
	}
	if e := s.MostRecentUserEmail(); e != "foo1@example.com" {
		return fmt.Errorf("Unexpected most recent email after user reg: %v", e)
	}

	// If we store user key, then that one should be returned
	if err := s.StoreUserKey("foo2@example.com", []byte("foo")); err != nil {
		return err
	}
	if s.AfterUserEmailStore != nil {
		s.AfterUserEmailStore("foo2@example.com")
	}
	if e := s.MostRecentUserEmail(); e != "foo2@example.com" {
		return fmt.Errorf("Unexpected most recent email after user key: %v", e)
	}

	// If we store user reg again, it should NOT should be returned
	if err := s.StoreUserReg("foo1@example.com", []byte("foo")); err != nil {
		return err
	}
	if s.AfterUserEmailStore != nil {
		s.AfterUserEmailStore("foo1@example.com")
	}
	if e := s.MostRecentUserEmail(); e != "foo1@example.com" {
		return fmt.Errorf("Unexpected most recent email after second user reg: %v", e)
	}
	return nil
}
