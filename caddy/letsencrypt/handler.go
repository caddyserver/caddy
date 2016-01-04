package letsencrypt

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const challengeBasePath = "/.well-known/acme-challenge"

// RequestCallback proxies challenge requests to ACME client if the
// request path starts with challengeBasePath. It returns true if it
// handled the request and no more needs to be done; it returns false
// if this call was a no-op and the request still needs handling.
func RequestCallback(w http.ResponseWriter, r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, challengeBasePath) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}

		hostname, _, err := net.SplitHostPort(r.URL.Host)
		if err != nil {
			hostname = r.URL.Host
		}

		upstream, err := url.Parse(scheme + "://" + hostname + ":" + AlternatePort)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] letsencrypt handler: %v", err)
			return true
		}

		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // client would use self-signed cert
		}
		proxy.ServeHTTP(w, r)

		return true
	}

	return false
}
