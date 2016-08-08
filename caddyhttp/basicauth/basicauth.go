// Package basicauth implements HTTP Basic Authentication for Caddy.
//
// This is useful for simple protections on a website, like requiring
// a password to access an admin interface. This package assumes a
// fairly small threat model.
package basicauth

import (
	"bufio"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jimstudt/http-authentication/basic"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// BasicAuth is middleware to protect resources with a username and password.
// Note that HTTP Basic Authentication is not secure by itself and should
// not be used to protect important assets without HTTPS. Even then, the
// security of HTTP Basic Auth is disputed. Use discretion when deciding
// what to protect with BasicAuth.
type BasicAuth struct {
	Next     httpserver.Handler
	SiteRoot string
	Rules    []Rule
}

// ServeHTTP implements the httpserver.Handler interface.
func (a BasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var hasAuth bool
	var isAuthenticated bool

	for _, rule := range a.Rules {
		for _, res := range rule.Resources {
			if !httpserver.Path(r.URL.Path).Matches(res) {
				continue
			}

			// Path matches; parse auth header
			username, password, ok := r.BasicAuth()
			hasAuth = true

			// Check credentials
			if !ok ||
				username != rule.Username ||
				!rule.Password(password) {
				continue
			}

			// Flag set only on successful authentication
			isAuthenticated = true
		}
	}

	if hasAuth {
		if !isAuthenticated {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			return http.StatusUnauthorized, nil
		}
		// "It's an older code, sir, but it checks out. I was about to clear them."
		return a.Next.ServeHTTP(w, r)
	}

	// Pass-thru when no paths match
	return a.Next.ServeHTTP(w, r)
}

// Rule represents a BasicAuth rule. A username and password
// combination protect the associated resources, which are
// file or directory paths.
type Rule struct {
	Username  string
	Password  func(string) bool
	Resources []string
}

// PasswordMatcher determines whether a password matches a rule.
type PasswordMatcher func(pw string) bool

var (
	htpasswords   map[string]map[string]PasswordMatcher
	htpasswordsMu sync.Mutex
)

// GetHtpasswdMatcher matches password rules.
func GetHtpasswdMatcher(filename, username, siteRoot string) (PasswordMatcher, error) {
	filename = filepath.Join(siteRoot, filename)
	htpasswordsMu.Lock()
	if htpasswords == nil {
		htpasswords = make(map[string]map[string]PasswordMatcher)
	}
	pm := htpasswords[filename]
	if pm == nil {
		fh, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("open %q: %v", filename, err)
		}
		defer fh.Close()
		pm = make(map[string]PasswordMatcher)
		if err = parseHtpasswd(pm, fh); err != nil {
			return nil, fmt.Errorf("parsing htpasswd %q: %v", fh.Name(), err)
		}
		htpasswords[filename] = pm
	}
	htpasswordsMu.Unlock()
	if pm[username] == nil {
		return nil, fmt.Errorf("username %q not found in %q", username, filename)
	}
	return pm[username], nil
}

func parseHtpasswd(pm map[string]PasswordMatcher, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.IndexByte(line, '#') == 0 {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return fmt.Errorf("malformed line, no color: %q", line)
		}
		user, encoded := line[:i], line[i+1:]
		for _, p := range basic.DefaultSystems {
			matcher, err := p(encoded)
			if err != nil {
				return err
			}
			if matcher != nil {
				pm[user] = matcher.MatchesPassword
				break
			}
		}
	}
	return scanner.Err()
}

// PlainMatcher returns a PasswordMatcher that does a constant-time
// byte comparison against the password passw.
func PlainMatcher(passw string) PasswordMatcher {
	// compare hashes of equal length instead of actual password
	// to avoid leaking password length
	passwHash := sha1.New()
	passwHash.Write([]byte(passw))
	passwSum := passwHash.Sum(nil)
	return func(pw string) bool {
		pwHash := sha1.New()
		pwHash.Write([]byte(pw))
		pwSum := pwHash.Sum(nil)
		return subtle.ConstantTimeCompare([]byte(pwSum), []byte(passwSum)) == 1
	}
}
