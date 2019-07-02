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

package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddytls"
	"github.com/mholt/certmagic"
)

func activateHTTPS(cctx caddy.Context) error {
	operatorPresent := !caddy.Started()

	if !caddy.Quiet && operatorPresent {
		fmt.Print("Activating privacy features... ")
	}

	ctx := cctx.(*httpContext)

	// pre-screen each config and earmark the ones that qualify for managed TLS
	markQualifiedForAutoHTTPS(ctx.siteConfigs)

	// place certificates and keys on disk
	for _, c := range ctx.siteConfigs {
		if !c.TLS.Managed {
			continue
		}
		if c.TLS.Manager.OnDemand != nil {
			continue // obtain these certificates on-demand instead
		}
		err := c.TLS.Manager.ObtainCert(c.TLS.Hostname, operatorPresent)
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
	// (skip if upgrading, because the parent process is likely already listening
	// on the ports we'd need to do ACME before we finish starting; parent process
	// already running renewal ticker, so renewal won't be missed anyway.)
	if !caddy.IsUpgrade() {
		ctx.instance.StorageMu.RLock()
		certCache, ok := ctx.instance.Storage[caddytls.CertCacheInstStorageKey].(*certmagic.Cache)
		ctx.instance.StorageMu.RUnlock()
		if ok && certCache != nil {
			err = certCache.RenewManagedCertificates(operatorPresent)
			if err != nil {
				return err
			}
		}
	}

	if !caddy.Quiet && operatorPresent {
		fmt.Println("done.")
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
// It will only change configs that are marked as managed but not on-demand, and
// assumes that certificates and keys are already on disk. If loadCertificates is
// true, the certificates will be loaded from disk into the cache for this process
// to use. If false, TLS will still be enabled and configured with default settings,
// but no certificates will be parsed loaded into the cache, and the returned error
// value will always be nil.
func enableAutoHTTPS(configs []*SiteConfig, loadCertificates bool) error {
	for _, cfg := range configs {
		if cfg == nil || cfg.TLS == nil || !cfg.TLS.Managed ||
			cfg.TLS.Manager == nil || cfg.TLS.Manager.OnDemand != nil {
			continue
		}
		cfg.TLS.Enabled = true
		cfg.Addr.Scheme = "https"
		if loadCertificates && certmagic.HostQualifies(cfg.TLS.Hostname) {
			_, err := cfg.TLS.Manager.CacheManagedCertificate(cfg.TLS.Hostname)
			if err != nil {
				return err
			}
		}

		// Make sure any config values not explicitly set are set to default
		caddytls.SetDefaultTLSParams(cfg.TLS)

		// Set default port of 443 if not explicitly set
		if cfg.Addr.Port == "" &&
			cfg.TLS.Enabled &&
			(!cfg.TLS.Manual || cfg.TLS.Manager.OnDemand != nil) &&
			cfg.Addr.Host != "localhost" {
			cfg.Addr.Port = strconv.Itoa(certmagic.HTTPSPort)
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
	httpPort := strconv.Itoa(certmagic.HTTPPort)
	httpsPort := strconv.Itoa(certmagic.HTTPSPort)
	for i, cfg := range allConfigs {
		if cfg.TLS.Managed &&
			!hostHasOtherPort(allConfigs, i, httpPort) &&
			(cfg.Addr.Port == httpsPort || !hostHasOtherPort(allConfigs, i, httpsPort)) {
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
// to listen on certmagic.HTTPPort. The TLS field of cfg must not be nil.
func redirPlaintextHost(cfg *SiteConfig) *SiteConfig {
	redirPort := cfg.Addr.Port
	if redirPort == strconv.Itoa(certmagic.HTTPSPort) {
		// By default, HTTPSPort should be DefaultHTTPSPort,
		// which of course doesn't need to be explicitly stated
		// in the Location header. Even if HTTPSPort is changed
		// so that it is no longer DefaultHTTPSPort, we shouldn't
		// append it to the URL in the Location because changing
		// the HTTPS port is assumed to be an internal-only change
		// (in other words, we assume port forwarding is going on);
		// but redirects go back to a presumably-external client.
		// (If redirect clients are also internal, that is more
		// advanced, and the user should configure HTTP->HTTPS
		// redirects themselves.)
		redirPort = ""
	}

	redirMiddleware := func(next Handler) Handler {
		return HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			// Construct the URL to which to redirect. Note that the Host in a
			// request might contain a port, but we just need the hostname from
			// it; and we'll set the port if needed.
			toURL := "https://"
			requestHost, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				requestHost = r.Host // Host did not contain a port, so use the whole value
			}
			if redirPort == "" {
				toURL += requestHost
			} else {
				toURL += net.JoinHostPort(requestHost, redirPort)
			}

			toURL += r.URL.RequestURI()

			w.Header().Set("Connection", "close")
			http.Redirect(w, r, toURL, http.StatusMovedPermanently)
			return 0, nil
		})
	}

	host := cfg.Addr.Host
	port := strconv.Itoa(certmagic.HTTPPort)
	addr := net.JoinHostPort(host, port)

	return &SiteConfig{
		Addr:       Address{Original: addr, Host: host, Port: port},
		ListenHost: cfg.ListenHost,
		middleware: []Middleware{redirMiddleware},
		TLS:        &caddytls.Config{Manager: cfg.TLS.Manager},
		Timeouts:   cfg.Timeouts,
	}
}
