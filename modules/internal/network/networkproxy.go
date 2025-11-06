package network

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(ProxyFromURL{})
	caddy.RegisterModule(ProxyFromNone{})
}

// The "url" proxy source uses the defined URL as the proxy
type ProxyFromURL struct {
	URL string `json:"url"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule implements Module.
func (p ProxyFromURL) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.network_proxy.url",
		New: func() caddy.Module {
			return &ProxyFromURL{}
		},
	}
}

func (p *ProxyFromURL) Provision(ctx caddy.Context) error {
	p.ctx = ctx
	p.logger = ctx.Logger()
	return nil
}

// Validate implements Validator.
func (p ProxyFromURL) Validate() error {
	if _, err := url.Parse(p.URL); err != nil {
		return err
	}
	return nil
}

// ProxyFunc implements ProxyFuncProducer.
func (p ProxyFromURL) ProxyFunc() func(*http.Request) (*url.URL, error) {
	if strings.Contains(p.URL, "{") && strings.Contains(p.URL, "}") {
		// courtesy of @ImpostorKeanu: https://github.com/caddyserver/caddy/pull/6397
		return func(r *http.Request) (*url.URL, error) {
			// retrieve the replacer from context.
			repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			if !ok {
				err := errors.New("failed to obtain replacer from request")
				p.logger.Error(err.Error())
				return nil, err
			}

			// apply placeholders to the value
			// note: h.ForwardProxyURL should never be empty at this point
			s := repl.ReplaceAll(p.URL, "")
			if s == "" {
				p.logger.Error("network_proxy URL was empty after applying placeholders",
					zap.String("initial_value", p.URL),
					zap.String("final_value", s),
					zap.String("hint", "check for invalid placeholders"))
				return nil, errors.New("empty value for network_proxy URL")
			}

			// parse the url
			pUrl, err := url.Parse(s)
			if err != nil {
				p.logger.Warn("failed to derive transport proxy from network_proxy URL")
				pUrl = nil
			} else if pUrl.Host == "" || strings.Split("", pUrl.Host)[0] == ":" {
				// url.Parse does not return an error on these values:
				//
				// - http://:80
				//   - pUrl.Host == ":80"
				// - /some/path
				//   - pUrl.Host == ""
				//
				// Super edge cases, but humans are human.
				err = errors.New("supplied network_proxy URL is missing a host value")
				pUrl = nil
			} else {
				p.logger.Debug("setting transport proxy url", zap.String("url", s))
			}

			return pUrl, err
		}
	}
	return func(r *http.Request) (*url.URL, error) {
		return url.Parse(p.URL)
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *ProxyFromURL) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	d.Next()
	p.URL = d.Val()
	return nil
}

// The "none" proxy source module disables the use of network proxy.
type ProxyFromNone struct{}

func (p ProxyFromNone) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.network_proxy.none",
		New: func() caddy.Module {
			return &ProxyFromNone{}
		},
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p ProxyFromNone) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// ProxyFunc implements ProxyFuncProducer.
func (p ProxyFromNone) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return nil
}

var (
	_ caddy.Module            = ProxyFromURL{}
	_ caddy.Provisioner       = (*ProxyFromURL)(nil)
	_ caddy.Validator         = ProxyFromURL{}
	_ caddy.ProxyFuncProducer = ProxyFromURL{}
	_ caddyfile.Unmarshaler   = (*ProxyFromURL)(nil)

	_ caddy.Module            = ProxyFromNone{}
	_ caddy.ProxyFuncProducer = ProxyFromNone{}
	_ caddyfile.Unmarshaler   = ProxyFromNone{}
)
