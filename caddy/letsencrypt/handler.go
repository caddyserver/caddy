package letsencrypt

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/mholt/caddy/middleware"
)

// Handler is a Caddy middleware that can proxy ACME requests
// to the real ACME endpoint. This is necessary to renew certificates
// while the server is running. Obviously, a site served on port
// 443 (HTTPS) binds to that port, so another listener created by
// our acme client can't bind successfully and solve the challenge.
// Thus, we chain this handler in so that it can, when activated,
// proxy ACME requests to an ACME client listening on an alternate
// port.
type Handler struct {
	sync.Mutex      // protects the ChallengePath property
	Next            middleware.Handler
	ChallengeActive int32  // use sync/atomic for speed to set/get this flag
	ChallengePath   string // the exact request path to match before proxying
}

// ServeHTTP is basically a no-op unless an ACME challenge is active on this host
// and the request path matches the expected path exactly.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// Only if challenge is active
	if atomic.LoadInt32(&h.ChallengeActive) == 1 {
		h.Lock()
		path := h.ChallengePath
		h.Unlock()

		// Request path must be correct; if so, proxy to ACME client
		if r.URL.Path == path {
			upstream, err := url.Parse("https://" + r.Host + ":" + alternatePort)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			proxy := httputil.NewSingleHostReverseProxy(upstream)
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // client uses self-signed cert
			}
			proxy.ServeHTTP(w, r)
			return 0, nil
		}
	}

	return h.Next.ServeHTTP(w, r)
}

// ChallengeOn enables h to proxy ACME requests.
func (h *Handler) ChallengeOn(challengePath string) {
	h.Lock()
	h.ChallengePath = challengePath
	h.Unlock()
	atomic.StoreInt32(&h.ChallengeActive, 1)
}

// ChallengeOff disables ACME proxying from this h.
func (h *Handler) ChallengeOff(success bool) {
	atomic.StoreInt32(&h.ChallengeActive, 0)
}
