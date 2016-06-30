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
//  stored. Do not change this value during the lifetime of the program.
var storageBasePath = filepath.Join(caddy.AssetsPath(), "acme")

func DefaultFileStorageCreator(caURL *url.URL) (Storage, error) {
	return fileStorage(filepath.Join(storageBasePath, caURL.Host)), nil
}

type fileStorage string

func (s fileStorage) clean() error {
	return os.RemoveAll(string(s))
}

func (s fileStorage) sites() string {
	return filepath.Join(string(s), "sites")
}

func (s fileStorage) site(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.sites(), domain)
}

func (s fileStorage) siteCertFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".crt")
}

func (s fileStorage) siteKeyFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".key")
}

func (s fileStorage) siteMetaFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".json")
}

func (s fileStorage) users() string {
	return filepath.Join(string(s), "users")
}

func (s fileStorage) user(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	return filepath.Join(s.users(), email)
}

// emailUsername returns the username portion of an
// email address (part before '@') or the original
// input if it can't find the "@" symbol.
func emailUsername(email string) string {
	at := strings.Index(email, "@")
	if at == -1 {
		return email
	} else if at == 0 {
		return email[1:]
	}
	return email[:at]
}

func (s fileStorage) userRegFile(email string) string {
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

func (s fileStorage) userKeyFile(email string) string {
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

func (s fileStorage) readFile(file string) ([]byte, error) {
	byts, err := ioutil.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, ErrStorageNotFound
	}
	return byts, err
}

func (s fileStorage) SiteInStorage(domain string) bool {
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

func (s fileStorage) LoadSiteCert(domain string) ([]byte, error) {
	return s.readFile(s.siteCertFile(domain))
}

func (s fileStorage) StoreSiteCert(domain string, byts []byte) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.siteCertFile(domain), byts, 0600)
}

func (s fileStorage) DeleteSiteCert(domain string) error {
	err := os.Remove(s.siteCertFile(domain))
	if os.IsNotExist(err) {
		return ErrStorageNotFound
	}
	return err
}

func (s fileStorage) LoadSiteKey(domain string) ([]byte, error) {
	return s.readFile(s.siteKeyFile(domain))
}

func (s fileStorage) StoreSiteKey(domain string, byts []byte) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.siteKeyFile(domain), byts, 0600)
}

func (s fileStorage) LoadSiteMeta(domain string) ([]byte, error) {
	return s.readFile(s.siteMetaFile(domain))
}

func (s fileStorage) StoreSiteMeta(domain string, byts []byte) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.siteMetaFile(domain), byts, 0600)
}

func (s fileStorage) LoadUserReg(email string) ([]byte, error) {
	return s.readFile(s.userRegFile(email))
}

func (s fileStorage) StoreUserReg(email string, byts []byte) error {
	err := os.MkdirAll(s.user(email), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.userRegFile(email), byts, 0600)
}

func (s fileStorage) LoadUserKey(email string) ([]byte, error) {
	return s.readFile(s.userKeyFile(email))
}

func (s fileStorage) StoreUserKey(email string, byts []byte) error {
	err := os.MkdirAll(s.user(email), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.userKeyFile(email), byts, 0600)
}

func (s fileStorage) MostRecentUserEmail() string {
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
