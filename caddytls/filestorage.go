package caddytls

import (
	"github.com/mholt/caddy"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// storageBasePath is the root path in which all TLS/ACME assets are
// stored. Do not change this value during the lifetime of the program.
var storageBasePath = filepath.Join(caddy.AssetsPath(), "acme")

// FileStorageCreator creates a new Storage instance backed by the local
// disk. The resulting Storage instance is guaranteed to be non-nil if
// there is no error. This can be used by "middleware" implementations that
// may want to proxy the disk storage.
func FileStorageCreator(caURL *url.URL) (Storage, error) {
	return FileStorage(filepath.Join(storageBasePath, caURL.Host)), nil
}

// FileStorage is a root directory and facilitates forming file paths derived
// from it. It is used to get file paths in a consistent, cross- platform way
// for persisting ACME assets on the file system.
type FileStorage string

// sites gets the directory that stores site certificate and keys.
func (s FileStorage) sites() string {
	return filepath.Join(string(s), "sites")
}

// site returns the path to the folder containing assets for domain.
func (s FileStorage) site(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.sites(), domain)
}

// siteCertFile returns the path to the certificate file for domain.
func (s FileStorage) siteCertFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".crt")
}

// siteKeyFile returns the path to domain's private key file.
func (s FileStorage) siteKeyFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".key")
}

// siteMetaFile returns the path to the domain's asset metadata file.
func (s FileStorage) siteMetaFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".json")
}

// users gets the directory that stores account folders.
func (s FileStorage) users() string {
	return filepath.Join(string(s), "users")
}

// user gets the account folder for the user with email
func (s FileStorage) user(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	return filepath.Join(s.users(), email)
}

// emailUsername returns the username portion of an email address (part before
// '@') or the original input if it can't find the "@" symbol.
func emailUsername(email string) string {
	at := strings.Index(email, "@")
	if at == -1 {
		return email
	} else if at == 0 {
		return email[1:]
	}
	return email[:at]
}

// userRegFile gets the path to the registration file for the user with the
// given email address.
func (s FileStorage) userRegFile(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	fileName := emailUsername(email)
	if fileName == "" {
		fileName = "registration"
	}
	return filepath.Join(s.user(email), fileName+".json")
}

// userKeyFile gets the path to the private key file for the user with the
// given email address.
func (s FileStorage) userKeyFile(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	fileName := emailUsername(email)
	if fileName == "" {
		fileName = "private"
	}
	return filepath.Join(s.user(email), fileName+".key")
}

// readFile abstracts a simple ioutil.ReadFile, making sure to return an
// ErrStorageNotFound instance when the file is not found.
func (s FileStorage) readFile(file string) ([]byte, error) {
	byts, err := ioutil.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, ErrStorageNotFound
	}
	return byts, err
}

// SiteInfoExists implements Storage.SiteInfoExists by checking for the
// presence of cert and key files.
func (s FileStorage) SiteInfoExists(domain string) bool {
	_, err := os.Stat(s.siteCertFile(domain))
	if err != nil {
		return false
	}
	_, err = os.Stat(s.siteKeyFile(domain))
	if err != nil {
		return false
	}
	return true
}

// LoadSiteCert implements Storage.LoadSiteCert by loading it from disk. If it
// is not present, the ErrStorageNotFound error instance is returned.
func (s FileStorage) LoadSiteCert(domain string) ([]byte, error) {
	return s.readFile(s.siteCertFile(domain))
}

// StoreSiteCert implements Storage.StoreSiteCert by writing it to disk. The
// base directories needed for the file are automatically created as needed.
func (s FileStorage) StoreSiteCert(domain string, byts []byte) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.siteCertFile(domain), byts, 0600)
}

// DeleteSiteCert implements Storage.DeleteSiteCert by deleting it from disk.
// If it is not present, the ErrStorageNotFound error instance is returned.
func (s FileStorage) DeleteSiteCert(domain string) error {
	err := os.Remove(s.siteCertFile(domain))
	if os.IsNotExist(err) {
		return ErrStorageNotFound
	}
	return err
}

// LoadSiteKey implements Storage.LoadSiteKey by loading it from disk. If it
// is not present, the ErrStorageNotFound error instance is returned.
func (s FileStorage) LoadSiteKey(domain string) ([]byte, error) {
	return s.readFile(s.siteKeyFile(domain))
}

// StoreSiteKey implements Storage.StoreSiteKey by writing it to disk. The
// base directories needed for the file are automatically created as needed.
func (s FileStorage) StoreSiteKey(domain string, byts []byte) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.siteKeyFile(domain), byts, 0600)
}

// LoadSiteMeta implements Storage.LoadSiteMeta by loading it from disk. If it
// is not present, the ErrStorageNotFound error instance is returned.
func (s FileStorage) LoadSiteMeta(domain string) ([]byte, error) {
	return s.readFile(s.siteMetaFile(domain))
}

// StoreSiteMeta implements Storage.StoreSiteMeta by writing it to disk. The
// base directories needed for the file are automatically created as needed.
func (s FileStorage) StoreSiteMeta(domain string, byts []byte) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.siteMetaFile(domain), byts, 0600)
}

// LoadUserReg implements Storage.LoadUserReg by loading it from disk. If it
// is not present, the ErrStorageNotFound error instance is returned.
func (s FileStorage) LoadUserReg(email string) ([]byte, error) {
	return s.readFile(s.userRegFile(email))
}

// StoreUserReg implements Storage.StoreUserReg by writing it to disk. The
// base directories needed for the file are automatically created as needed.
func (s FileStorage) StoreUserReg(email string, byts []byte) error {
	err := os.MkdirAll(s.user(email), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.userRegFile(email), byts, 0600)
}

// LoadUserKey implements Storage.LoadUserKey by loading it from disk. If it
// is not present, the ErrStorageNotFound error instance is returned.
func (s FileStorage) LoadUserKey(email string) ([]byte, error) {
	return s.readFile(s.userKeyFile(email))
}

// StoreUserKey implements Storage.StoreUserKey by writing it to disk. The
// base directories needed for the file are automatically created as needed.
func (s FileStorage) StoreUserKey(email string, byts []byte) error {
	err := os.MkdirAll(s.user(email), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.userKeyFile(email), byts, 0600)
}

// MostRecentUserEmail implements Storage.MostRecentEmail by finding the most
// recently written sub directory in the users' directory. It is named after
// the email address. This corresponds to the most recent call to StoreUserReg
// or StoreUserKey.
func (s FileStorage) MostRecentUserEmail() string {
	userDirs, err := ioutil.ReadDir(s.users())
	if err != nil {
		return ""
	}
	var mostRecent os.FileInfo
	for _, dir := range userDirs {
		if !dir.IsDir() {
			continue
		}
		if mostRecent == nil || dir.ModTime().After(mostRecent.ModTime()) {
			mostRecent = dir
		}
	}
	if mostRecent != nil {
		return mostRecent.Name()
	}
	return ""
}
