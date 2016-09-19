package caddytls

import (
	"crypto/tls"
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestMakeTLSConfigProtocolVersions(t *testing.T) {
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

func TestMakeTLSConfigPreferServerCipherSuites(t *testing.T) {
	// prefer server cipher suites
	configs := []*Config{{Enabled: true, PreferServerCipherSuites: true}}
	result, err := MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if got, want := result.PreferServerCipherSuites, true; got != want {
		t.Errorf("Expected PreferServerCipherSuites==%v but got %v", want, got)
	}

	// make sure we don't get an error if there's a conflict
	// when both of the configs have TLS disabled
	configs = []*Config{
		{Enabled: false, PreferServerCipherSuites: false},
		{Enabled: false, PreferServerCipherSuites: true},
	}
	result, err = MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Did not expect an error when TLS is disabled, but got '%v'", err)
	}
	if result != nil {
		t.Errorf("Expected nil result because TLS disabled, got: %+v", err)
	}
}

func TestMakeTLSConfigTLSEnabledDisabled(t *testing.T) {
	// verify handling when Enabled is true and false
	configs := []*Config{
		{Enabled: true},
		{Enabled: false},
	}
	_, err := MakeTLSConfig(configs)
	if err == nil {
		t.Fatalf("Expected an error, but got %v", err)
	}

	// verify that when disabled, a nil pair is returned
	configs = []*Config{{}, {}}
	result, err := MakeTLSConfig(configs)
	if err != nil {
		t.Errorf("Did not expect an error, but got %v", err)
	}
	if result != nil {
		t.Errorf("Expected a nil *tls.Config result, got %+v", result)
	}
}

func TestMakeTLSConfigCipherSuites(t *testing.T) {
	// ensure cipher suites are unioned and
	// that TLS_FALLBACK_SCSV is prepended
	configs := []*Config{
		{Enabled: true, Ciphers: []uint16{0xc02c, 0xc030}},
		{Enabled: true, Ciphers: []uint16{0xc012, 0xc030, 0xc00a}},
	}
	result, err := MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	expected := []uint16{tls.TLS_FALLBACK_SCSV, 0xc02c, 0xc030, 0xc012, 0xc00a}
	if !reflect.DeepEqual(result.CipherSuites, expected) {
		t.Errorf("Expected ciphers %v but got %v", expected, result.CipherSuites)
	}

	// use default suites if none specified
	configs = []*Config{{Enabled: true}}
	result, err = MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	expected = append([]uint16{tls.TLS_FALLBACK_SCSV}, defaultCiphers...)
	if !reflect.DeepEqual(result.CipherSuites, expected) {
		t.Errorf("Expected default ciphers %v but got %v", expected, result.CipherSuites)
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
	RegisterStorageProvider("fake-TestStorageForLowercasesAndPrefixesScheme", func(caURL *url.URL) (Storage, error) {
		resultStr = caURL.String()
		return nil, nil
	})
	c := &Config{
		StorageProvider: "fake-TestStorageForLowercasesAndPrefixesScheme",
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
	if _, ok := s.(*FileStorage); !ok {
		t.Fatalf("Unexpected storage type: %#v", s)
	}
}

func TestStorageForCustom(t *testing.T) {
	storage := fakeStorage("fake-TestStorageForCustom")
	RegisterStorageProvider("fake-TestStorageForCustom", func(caURL *url.URL) (Storage, error) { return storage, nil })
	c := &Config{
		StorageProvider: "fake-TestStorageForCustom",
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
	RegisterStorageProvider("fake-TestStorageForCustomError", func(caURL *url.URL) (Storage, error) { return nil, errors.New("some error") })
	c := &Config{
		StorageProvider: "fake-TestStorageForCustomError",
	}
	if _, err := c.StorageFor("example.com"); err == nil {
		t.Fatal("Expecting error")
	}
}

func TestStorageForCustomNil(t *testing.T) {
	// Should fall through to the default
	c := &Config{StorageProvider: ""}
	s, err := c.StorageFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*FileStorage); !ok {
		t.Fatalf("Unexpected storage type: %#v", s)
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

func (s fakeStorage) TryLock(domain string) (Waiter, error) {
	panic("no impl")
}

func (s fakeStorage) Unlock(domain string) error {
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
