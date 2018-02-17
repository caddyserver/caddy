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
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/caddy"
)

func init() {
	RegisterStorageProvider("file", NewFileStorage)
}

// storageBasePath is the root path in which all TLS/ACME assets are
// stored. Do not change this value during the lifetime of the program.
var storageBasePath = filepath.Join(caddy.AssetsPath(), "acme")

// NewFileStorage is a StorageConstructor function that creates a new
// Storage instance backed by the local disk. The resulting Storage
// instance is guaranteed to be non-nil if there is no error.
func NewFileStorage(caURL *url.URL) (Storage, error) {
	storage := &FileStorage{Path: filepath.Join(storageBasePath, caURL.Host)}
	storage.Locker = &fileStorageLock{caURL: caURL.Host, storage: storage}
	return storage, nil
}

// FileStorage facilitates forming file paths derived from a root
// directory. It is used to get file paths in a consistent,
// cross-platform way or persisting ACME assets on the file system.
type FileStorage struct {
	Path string
	Locker
}

// sites gets the directory that stores site certificate and keys.
func (s *FileStorage) sites() string {
	return filepath.Join(s.Path, "sites")
}

// site returns the path to the folder containing assets for domain.
func (s *FileStorage) site(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.sites(), domain)
}

// siteCertFile returns the path to the certificate file for domain.
func (s *FileStorage) siteCertFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".crt")
}

// siteKeyFile returns the path to domain's private key file.
func (s *FileStorage) siteKeyFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".key")
}

// siteMetaFile returns the path to the domain's asset metadata file.
func (s *FileStorage) siteMetaFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.site(domain), domain+".json")
}

// users gets the directory that stores account folders.
func (s *FileStorage) users() string {
	return filepath.Join(s.Path, "users")
}

// user gets the account folder for the user with email
func (s *FileStorage) user(email string) string {
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
func (s *FileStorage) userRegFile(email string) string {
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
func (s *FileStorage) userKeyFile(email string) string {
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
// ErrNotExist instance when the file is not found.
func (s *FileStorage) readFile(file string) ([]byte, error) {
	b, err := ioutil.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, ErrNotExist(err)
	}
	return b, err
}

// SiteExists implements Storage.SiteExists by checking for the presence of
// cert and key files.
func (s *FileStorage) SiteExists(domain string) (bool, error) {
	_, err := os.Stat(s.siteCertFile(domain))
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	_, err = os.Stat(s.siteKeyFile(domain))
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadSite implements Storage.LoadSite by loading it from disk. If it is not
// present, an instance of ErrNotExist is returned.
func (s *FileStorage) LoadSite(domain string) (*SiteData, error) {
	var err error
	siteData := new(SiteData)
	siteData.Cert, err = s.readFile(s.siteCertFile(domain))
	if err != nil {
		return nil, err
	}
	siteData.Key, err = s.readFile(s.siteKeyFile(domain))
	if err != nil {
		return nil, err
	}
	siteData.Meta, err = s.readFile(s.siteMetaFile(domain))
	if err != nil {
		return nil, err
	}
	return siteData, nil
}

// StoreSite implements Storage.StoreSite by writing it to disk. The base
// directories needed for the file are automatically created as needed.
func (s *FileStorage) StoreSite(domain string, data *SiteData) error {
	err := os.MkdirAll(s.site(domain), 0700)
	if err != nil {
		return fmt.Errorf("making site directory: %v", err)
	}
	err = ioutil.WriteFile(s.siteCertFile(domain), data.Cert, 0600)
	if err != nil {
		return fmt.Errorf("writing certificate file: %v", err)
	}
	err = ioutil.WriteFile(s.siteKeyFile(domain), data.Key, 0600)
	if err != nil {
		return fmt.Errorf("writing key file: %v", err)
	}
	err = ioutil.WriteFile(s.siteMetaFile(domain), data.Meta, 0600)
	if err != nil {
		return fmt.Errorf("writing cert meta file: %v", err)
	}
	log.Printf("[INFO][%v] Certificate written to disk: %v", domain, s.siteCertFile(domain))
	return nil
}

// DeleteSite implements Storage.DeleteSite by deleting just the cert from
// disk. If it is not present, an instance of ErrNotExist is returned.
func (s *FileStorage) DeleteSite(domain string) error {
	err := os.Remove(s.siteCertFile(domain))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotExist(err)
		}
		return err
	}
	return nil
}

// LoadUser implements Storage.LoadUser by loading it from disk. If it is not
// present, an instance of ErrNotExist is returned.
func (s *FileStorage) LoadUser(email string) (*UserData, error) {
	var err error
	userData := new(UserData)
	userData.Reg, err = s.readFile(s.userRegFile(email))
	if err != nil {
		return nil, err
	}
	userData.Key, err = s.readFile(s.userKeyFile(email))
	if err != nil {
		return nil, err
	}
	return userData, nil
}

// StoreUser implements Storage.StoreUser by writing it to disk. The base
// directories needed for the file are automatically created as needed.
func (s *FileStorage) StoreUser(email string, data *UserData) error {
	err := os.MkdirAll(s.user(email), 0700)
	if err != nil {
		return fmt.Errorf("making user directory: %v", err)
	}
	err = ioutil.WriteFile(s.userRegFile(email), data.Reg, 0600)
	if err != nil {
		return fmt.Errorf("writing user registration file: %v", err)
	}
	err = ioutil.WriteFile(s.userKeyFile(email), data.Key, 0600)
	if err != nil {
		return fmt.Errorf("writing user key file: %v", err)
	}
	return nil
}

// MostRecentUserEmail implements Storage.MostRecentUserEmail by finding the
// most recently written sub directory in the users' directory. It is named
// after the email address. This corresponds to the most recent call to
// StoreUser.
func (s *FileStorage) MostRecentUserEmail() string {
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
