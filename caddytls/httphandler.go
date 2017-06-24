package caddytls

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const challengeBasePath = "/.well-known/acme-challenge"

// HTTPChallengeHandler proxies challenge requests to ACME client if the
// request path starts with challengeBasePath. It returns true if it
// handled the request and no more needs to be done; it returns false
// if this call was a no-op and the request still needs handling.
func HTTPChallengeHandler(w http.ResponseWriter, r *http.Request, listenHost, altPort string) bool {
	if !strings.HasPrefix(r.URL.Path, challengeBasePath) {
		return false
	}
	if DisableHTTPChallenge {
		return false
	}
	if !namesObtaining.Has(r.Host) {
		return false
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if listenHost == "" {
		listenHost = "localhost"
	}

	upstream, err := url.Parse(fmt.Sprintf("%s://%s:%s", scheme, listenHost, altPort))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] ACME proxy handler: %v", err)
		return true
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.ServeHTTP(w, r)

	return true
}
