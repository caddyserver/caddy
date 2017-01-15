package httpserver

import (
	"fmt"
	"net"
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddytls"
)

func activateHTTPS(cctx caddy.Context) error {
	operatorPresent := !caddy.Started()

	if !caddy.Quiet && operatorPresent {
		fmt.Print("Activating privacy features...")
	}

	ctx := cctx.(*httpContext)

	// pre-screen each config and earmark the ones that qualify for managed TLS
	markQualifiedForAutoHTTPS(ctx.siteConfigs)

	// place certificates and keys on disk
	for _, c := range ctx.siteConfigs {
		err := c.TLS.ObtainCert(c.TLS.Hostname, operatorPresent)
		if err != nil {
			return err
		}
	}

	// update TLS configurations
	err := enableAutoHTTPS(ctx.siteConfigs, true)
	if err != nil {
		return err
	}

	// set up redirects
	ctx.siteConfigs = makePlaintextRedirects(ctx.siteConfigs)

	// renew all relevant certificates that need renewal. this is important
	// to do right away so we guarantee that renewals aren't missed, and
	// also the user can respond to any potential errors that occur.
	err = caddytls.RenewManagedCertificates(true)
	if err != nil {
		return err
	}

	if !caddy.Quiet && operatorPresent {
		fmt.Println(" done.")
	}

	return nil
}

// markQualifiedForAutoHTTPS scans each config and, if it
// qualifies for managed TLS, it sets the Managed field of
// the TLS config to true.
func markQualifiedForAutoHTTPS(configs []*SiteConfig) {
	for _, cfg := range configs {
		if caddytls.QualifiesForManagedTLS(cfg) && cfg.Addr.Scheme != "http" {
			cfg.TLS.Managed = true
		}
	}
}

// enableAutoHTTPS configures each config to use TLS according to default settings.
// It will only change configs that are marked as managed, and assumes that
// certificates and keys are already on disk. If loadCertificates is true,
// the certificates will be loaded from disk into the cache for this process
// to use. If false, TLS will still be enabled and configured with default
// settings, but no certificates will be parsed loaded into the cache, and
// the returned error value will always be nil.
func enableAutoHTTPS(configs []*SiteConfig, loadCertificates bool) error {
	for _, cfg := range configs {
		if cfg == nil || cfg.TLS == nil || !cfg.TLS.Managed {
			continue
		}
		cfg.TLS.Enabled = true
		cfg.Addr.Scheme = "https"
		if loadCertificates && caddytls.HostQualifies(cfg.Addr.Host) {
			_, err := caddytls.CacheManagedCertificate(cfg.Addr.Host, cfg.TLS)
			if err != nil {
				return err
			}
		}

		// Make sure any config values not explicitly set are set to default
		caddytls.SetDefaultTLSParams(cfg.TLS)

		// Set default port of 443 if not explicitly set
		if cfg.Addr.Port == "" &&
			cfg.TLS.Enabled &&
			(!cfg.TLS.Manual || cfg.TLS.OnDemand) &&
			cfg.Addr.Host != "localhost" {
			cfg.Addr.Port = "443"
		}
	}
	return nil
}

// makePlaintextRedirects sets up redirects from port 80 to the relevant HTTPS
// hosts. You must pass in all configs, not just configs that qualify, since
// we must know whether the same host already exists on port 80, and those would
// not be in a list of configs that qualify for automatic HTTPS. This function will
// only set up redirects for configs that qualify. It returns the updated list of
// all configs.
func makePlaintextRedirects(allConfigs []*SiteConfig) []*SiteConfig {
	for i, cfg := range allConfigs {
		if cfg.TLS.Managed &&
			!hostHasOtherPort(allConfigs, i, "80") &&
			(cfg.Addr.Port == "443" || !hostHasOtherPort(allConfigs, i, "443")) {
			allConfigs = append(allConfigs, redirPlaintextHost(cfg))
		}
	}
	return allConfigs
}

// hostHasOtherPort returns true if there is another config in the list with the same
// hostname that has port otherPort, or false otherwise. All the configs are checked
// against the hostname of allConfigs[thisConfigIdx].
func hostHasOtherPort(allConfigs []*SiteConfig, thisConfigIdx int, otherPort string) bool {
	for i, otherCfg := range allConfigs {
		if i == thisConfigIdx {
			continue // has to be a config OTHER than the one we're comparing against
		}
		if otherCfg.Addr.Host == allConfigs[thisConfigIdx].Addr.Host &&
			otherCfg.Addr.Port == otherPort {
			return true
		}
	}
	return false
}

// redirPlaintextHost returns a new plaintext HTTP configuration for
// a virtualHost that simply redirects to cfg, which is assumed to
// be the HTTPS configuration. The returned configuration is set
// to listen on port 80. The TLS field of cfg must not be nil.
func redirPlaintextHost(cfg *SiteConfig) *SiteConfig {
	redirPort := cfg.Addr.Port
	if redirPort == "443" {
		// default port is redundant
		redirPort = ""
	}
	redirMiddleware := func(next Handler) Handler {
		return HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			toURL := "https://" + r.Host
			if redirPort != "" {
				toURL += ":" + redirPort
			}
			toURL += r.URL.RequestURI()
			w.Header().Set("Connection", "close")
			http.Redirect(w, r, toURL, http.StatusMovedPermanently)
			return 0, nil
		})
	}
	host := cfg.Addr.Host
	port := "80"
	addr := net.JoinHostPort(host, port)
	return &SiteConfig{
		Addr:       Address{Original: addr, Host: host, Port: port},
		ListenHost: cfg.ListenHost,
		middleware: []Middleware{redirMiddleware},
		TLS:        &caddytls.Config{AltHTTPPort: cfg.TLS.AltHTTPPort},
	}
}
