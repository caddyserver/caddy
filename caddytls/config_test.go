package caddytls

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestStorageForNoURL(t *testing.T) {
	c := &Config{}
	if _, err := c.StorageFor(""); err == nil {
		t.Fatal("Expected error on empty URL")
	}
}

func TestStorageForLowercasesAndPrefixesScheme(t *testing.T) {
	resultStr := ""
	c := &Config{
		StorageCreator: func(caURL *url.URL) (Storage, error) {
			resultStr = caURL.String()
			return nil, nil
		},
	}
	if _, err := c.StorageFor("EXAMPLE.COM/BLAH"); err != nil {
		t.Fatal(err)
	}
	if resultStr != "https://example.com/blah" {
		t.Fatalf("Unexpected CA URL string: %v", resultStr)
	}
}

func TestStorageForBadURL(t *testing.T) {
	c := &Config{}
	if _, err := c.StorageFor("http://192.168.0.%31/"); err == nil {
		t.Fatal("Expected error for bad URL")
	}
}

func TestStorageForDefault(t *testing.T) {
	c := &Config{}
	s, err := c.StorageFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(s).Name() != "FileStorage" {
		t.Fatalf("Unexpected storage type: %v", reflect.TypeOf(s).Name())
	}
}

func TestStorageForCustom(t *testing.T) {
	storage := fakeStorage("fake")
	c := &Config{
		StorageCreator: func(caURL *url.URL) (Storage, error) {
			return storage, nil
		},
	}
	s, err := c.StorageFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if s != storage {
		t.Fatal("Unexpected storage")
	}
}

func TestStorageForCustomError(t *testing.T) {
	c := &Config{
		StorageCreator: func(caURL *url.URL) (Storage, error) {
			return nil, errors.New("some error")
		},
	}
	if _, err := c.StorageFor("example.com"); err == nil {
		t.Fatal("Expecting error")
	}
}

func TestStorageForCustomNil(t *testing.T) {
	// Should fall through to the default
	c := &Config{
		StorageCreator: func(caURL *url.URL) (Storage, error) {
			return nil, nil
		},
	}
	s, err := c.StorageFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(s).Name() != "FileStorage" {
		t.Fatalf("Unexpected storage type: %v", reflect.TypeOf(s).Name())
	}
}

type fakeStorage string

func (s fakeStorage) SiteInfoExists(domain string) bool {
	panic("no impl")
}

func (s fakeStorage) LoadSiteCert(domain string) ([]byte, error) {
	panic("no impl")
}

func (s fakeStorage) StoreSiteCert(domain string, byts []byte) error {
	panic("no impl")
}

func (s fakeStorage) DeleteSiteCert(domain string) error {
	panic("no impl")
}

func (s fakeStorage) LoadSiteKey(domain string) ([]byte, error) {
	panic("no impl")
}

func (s fakeStorage) StoreSiteKey(domain string, byts []byte) error {
	panic("no impl")
}

func (s fakeStorage) LoadSiteMeta(domain string) ([]byte, error) {
	panic("no impl")
}

func (s fakeStorage) StoreSiteMeta(domain string, byts []byte) error {
	panic("no impl")
}

func (s fakeStorage) LoadUserReg(email string) ([]byte, error) {
	panic("no impl")
}

func (s fakeStorage) StoreUserReg(email string, byts []byte) error {
	panic("no impl")
}

func (s fakeStorage) LoadUserKey(email string) ([]byte, error) {
	panic("no impl")
}

func (s fakeStorage) StoreUserKey(email string, byts []byte) error {
	panic("no impl")
}

func (s fakeStorage) MostRecentUserEmail() string {
	panic("no impl")
}
