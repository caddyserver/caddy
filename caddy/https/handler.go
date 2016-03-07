package https

import (
	"crypto/tls"
	"log"
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

		upstream, err := url.Parse(scheme + "://localhost:" + AlternatePort)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] ACME proxy handler: %v", err)
			return true
		}

		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // solver uses self-signed certs
		}
		proxy.ServeHTTP(w, r)

		return true
	}

	return false
}
