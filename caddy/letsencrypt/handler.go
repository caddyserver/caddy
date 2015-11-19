package letsencrypt

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mholt/caddy/middleware"
)

const challengeBasePath = "/.well-known/acme-challenge"

// Handler is a Caddy middleware that can proxy ACME challenge
// requests to the real ACME client endpoint. This is necessary
// to renew certificates while the server is running.
type Handler struct {
	Next middleware.Handler
	//ChallengeActive int32 // (TODO) use sync/atomic to set/get this flag safely and efficiently
}

// ServeHTTP is basically a no-op unless an ACME challenge is active on this host
// and the request path matches the expected path exactly.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// Proxy challenge requests to ACME client
	// TODO: Only do this if a challenge is active?
	if strings.HasPrefix(r.URL.Path, challengeBasePath) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}

		hostname, _, err := net.SplitHostPort(r.URL.Host)
		if err != nil {
			hostname = r.URL.Host
		}

		upstream, err := url.Parse(scheme + "://" + hostname + ":" + alternatePort)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // client would use self-signed cert
		}
		proxy.ServeHTTP(w, r)

		return 0, nil
	}

	return h.Next.ServeHTTP(w, r)
}
