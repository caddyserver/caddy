package caddytls

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/mholt/caddy"
)

// StorageFor gets the storage value associated with the
// caURL, which should be unique for every different
// ACME CA.
func StorageFor(caURL string) (Storage, error) {
	if caURL == "" {
		caURL = DefaultCAUrl
	}
	if caURL == "" {
		return "", fmt.Errorf("cannot create storage without CA URL")
	}
	caURL = strings.ToLower(caURL)

	// scheme required or host will be parsed as path (as of Go 1.6)
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}

	u, err := url.Parse(caURL)
	if err != nil {
		return "", fmt.Errorf("%s: unable to parse CA URL: %v", caURL, err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("%s: no host in CA URL", caURL)
	}

	return Storage(filepath.Join(storageBasePath, u.Host)), nil
}

// Storage is a root directory and facilitates
// forming file paths derived from it. It is used
// to get file paths in a consistent, cross-
// platform way for persisting ACME assets.
// on the file system.
type Storage string

// Sites gets the directory that stores site certificate and keys.
func (s Storage) Sites() string {
	return filepath.Join(string(s), "sites")
}

// Site returns the path to the folder containing assets for domain.
func (s Storage) Site(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.Sites(), domain)
}

// SiteCertFile returns the path to the certificate file for domain.
func (s Storage) SiteCertFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.Site(domain), domain+".crt")
}

// SiteKeyFile returns the path to domain's private key file.
func (s Storage) SiteKeyFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.Site(domain), domain+".key")
}

// SiteMetaFile returns the path to the domain's asset metadata file.
func (s Storage) SiteMetaFile(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.Site(domain), domain+".json")
}

// Users gets the directory that stores account folders.
func (s Storage) Users() string {
	return filepath.Join(string(s), "users")
}

// User gets the account folder for the user with email.
func (s Storage) User(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	return filepath.Join(s.Users(), email)
}

// UserRegFile gets the path to the registration file for
// the user with the given email address.
func (s Storage) UserRegFile(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	fileName := emailUsername(email)
	if fileName == "" {
		fileName = "registration"
	}
	return filepath.Join(s.User(email), fileName+".json")
}

// UserKeyFile gets the path to the private key file for
// the user with the given email address.
func (s Storage) UserKeyFile(email string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	fileName := emailUsername(email)
	if fileName == "" {
		fileName = "private"
	}
	return filepath.Join(s.User(email), fileName+".key")
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

// storageBasePath is the root path in which all TLS/ACME assets are
//  stored. Do not change this value during the lifetime of the program.
var storageBasePath = filepath.Join(caddy.AssetsPath(), "acme")
