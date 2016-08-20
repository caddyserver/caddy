package caddytls

import (
	"crypto/tls"
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestMakeTLSConfig(t *testing.T) {
	// same min and max protocol versions
	configs := []*Config{
		{
			Enabled:            true,
			ProtocolMinVersion: tls.VersionTLS12,
			ProtocolMaxVersion: tls.VersionTLS12,
		},
	}
	result, err := MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if got, want := result.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("Expected min version to be %x, got %x", want, got)
	}
	if got, want := result.MaxVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("Expected max version to be %x, got %x", want, got)
	}
}

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

func (s fakeStorage) SiteExists(domain string) (bool, error) {
	panic("no impl")
}

func (s fakeStorage) LoadSite(domain string) (*SiteData, error) {
	panic("no impl")
}

func (s fakeStorage) StoreSite(domain string, data *SiteData) error {
	panic("no impl")
}

func (s fakeStorage) DeleteSite(domain string) error {
	panic("no impl")
}

func (s fakeStorage) LockRegister(domain string) (bool, error) {
	panic("no impl")
}

func (s fakeStorage) UnlockRegister(domain string) error {
	panic("no impl")
}

func (s fakeStorage) LoadUser(email string) (*UserData, error) {
	panic("no impl")
}

func (s fakeStorage) StoreUser(email string, data *UserData) error {
	panic("no impl")
}

func (s fakeStorage) MostRecentUserEmail() string {
	panic("no impl")
}
