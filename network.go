package caddy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

func init() {
	RegisterModule(ProxyFromEnvironment{})
	RegisterModule(ProxyFromURL{})
}

type ProxyFuncProducer interface {
	ProxyFunc() func(*http.Request) (*url.URL, error)
}

type ProxyFromEnvironment struct{}

// ProxyFunc implements ProxyFuncProducer.
func (p ProxyFromEnvironment) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment
}

// CaddyModule implements Module.
func (p ProxyFromEnvironment) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID: "caddy.network_proxy.source.environment",
		New: func() Module {
			return ProxyFromEnvironment{}
		},
	}
}

type ProxyFromURL struct {
	URL string `json:"url"`

	ctx    Context
	logger *zap.Logger
}

// CaddyModule implements Module.
func (p ProxyFromURL) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID: "caddy.network_proxy.source.url",
		New: func() Module {
			return &ProxyFromURL{}
		},
	}
}

func (p *ProxyFromURL) Provision(ctx Context) error {
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
			repl, ok := r.Context().Value(ReplacerCtxKey).(*Replacer)
			if !ok {
				err := errors.New("failed to obtain replacer from request")
				p.logger.Error(err.Error())
				return nil, err
			}

			// apply placeholders to the value
			// note: h.ForwardProxyURL should never be empty at this point
			s := repl.ReplaceAll(p.URL, "")
			if s == "" {
				p.logger.Error("forward_proxy_url was empty after applying placeholders",
					zap.String("initial_value", p.URL),
					zap.String("final_value", s),
					zap.String("hint", "check for invalid placeholders"))
				return nil, errors.New("empty value for forward_proxy_url")
			}

			// parse the url
			pUrl, err := url.Parse(s)
			if err != nil {
				p.logger.Warn("failed to derive transport proxy from forward_proxy_url")
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
				err = errors.New("supplied forward_proxy_url is missing a host value")
				pUrl = nil
			} else {
				p.logger.Debug("setting transport proxy url", zap.String("url", s))
			}

			return pUrl, err
		}
	}
	return func(*http.Request) (*url.URL, error) {
		return url.Parse(p.URL)
	}
}

var (
	_ Module            = ProxyFromEnvironment{}
	_ ProxyFuncProducer = ProxyFromEnvironment{}
	_ Module            = ProxyFromURL{}
	_ Provisioner       = &ProxyFromURL{}
	_ Validator         = ProxyFromURL{}
	_ ProxyFuncProducer = ProxyFromURL{}
)
