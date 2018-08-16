// Package digestauth implements HTTP Digest Authentication for Caddy.
//
// This is useful for simple protections on a website, like requiring
// a password to access an admin interface. This package assumes a
// fairly small threat model.
package digestauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// DigestAuth is middleware to protect resources with a username and password.
// Note that HTTP Digest Authentication is not secure by itself and should
// not be used to protect important assets without HTTPS. Even then, the
// security of HTTP Digest Auth is disputed. Use discretion when deciding
// what to protect with DigestAuth.
type DigestAuth struct {
	Next     httpserver.Handler
	SiteRoot string
	Rules    []Rule
}

// ServeHTTP implements the httpserver.Handler interface.
func (a DigestAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	authHeader := r.Header.Get("Authorization")

	for _, rule := range a.Rules {
		for _, res := range rule.Resources {
			if !httpserver.Path(r.URL.Path).Matches(res) {
				continue
			}

			rule.Digester.Log(log.New(os.Stdout, "digestauth: ", log.Ltime))

			if authHeader == "" || !strings.HasPrefix(authHeader, "Digest ") {
				n, err := rule.Digester.MakeNonce()
				if err != nil {
					return http.StatusUnauthorized, err
				}

				w.Header().Add("WWW-Authenticate", "Digest realm=\""+rule.Realm+
					"\", algorithm=\"MD5-sess\", qop=\"auth,auth-int\", nonce=\""+
					n.Value()+"\"")
				return http.StatusUnauthorized, nil
			}

			rest := authHeader[7:]
			params, err := parseAuthorization(strings.NewReader(rest))
			if err != nil {
				return http.StatusBadRequest, err
			}

			code, _, _ := rule.Digester.EvaluateDigest(params, r.Method)
			switch code {
			case http.StatusOK:
				// don't do anything, we are authorized, pass along to the next handler
			case http.StatusUnauthorized:
				n, err := rule.Digester.MakeNonce()
				if err != nil {
					return http.StatusInternalServerError, err
				}

				fmt.Printf("")
				w.Header().Add("WWW-Authenticate", "Digest realm=\""+rule.Realm+
					"\", algorithm=\"MD5-sess\", qop=\"auth,auth-int\", nonce=\""+
					n.Value()+"\"")
				return http.StatusUnauthorized, nil
			default:
				return code, nil
			}

			// let upstream middleware (e.g. fastcgi and cgi) know about authenticated
			// user; this replaces the request with a wrapped instance
			r = r.WithContext(context.WithValue(r.Context(),
				httpserver.RemoteUserCtxKey, params["username"]))
		}
	}

	// Pass-through when no paths match
	return a.Next.ServeHTTP(w, r)
}

// Rule represents a DigestAuth rule. A user storage protects
// the associated resources, which are file or directory paths.
type Rule struct {
	Resources []string
	Realm     string // See RFC 1945 and RFC 2617, default: "Restricted"
	Opaque    string
	Users     UserStore
	Digester  Digest
}
