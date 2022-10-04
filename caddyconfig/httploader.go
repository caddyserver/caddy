// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddyconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(HTTPLoader{})
}

// HTTPLoader can load Caddy configs over HTTP(S). It can adapt the config
// based on the Content-Type header of the HTTP response.
type HTTPLoader struct {
	// The method for the request. Default: GET
	Method string `json:"method,omitempty"`

	// The URL of the request.
	URL string `json:"url,omitempty"`

	// HTTP headers to add to the request.
	Headers http.Header `json:"header,omitempty"`

	// Maximum time allowed for a complete connection and request.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// The number of seconds to wait in between attempts to call `URL`.
	// Defaults to 0, indicating no retries.
	RetryDelay time.Duration `json:"retry_delay,omitempty"`

	TLS *struct {
		// Present this instance's managed remote identity credentials to the server.
		UseServerIdentity bool `json:"use_server_identity,omitempty"`

		// PEM-encoded client certificate filename to present to the server.
		ClientCertificateFile string `json:"client_certificate_file,omitempty"`

		// PEM-encoded key to use with the client certificate.
		ClientCertificateKeyFile string `json:"client_certificate_key_file,omitempty"`

		// List of PEM-encoded CA certificate files to add to the same trust
		// store as RootCAPool (or root_ca_pool in the JSON).
		RootCAPEMFiles []string `json:"root_ca_pem_files,omitempty"`
	} `json:"tls,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (HTTPLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.config_loaders.http",
		New: func() caddy.Module { return new(HTTPLoader) },
	}
}

// LoadConfig loads a Caddy config.
func (hl HTTPLoader) LoadConfig(ctx caddy.Context) ([]byte, error) {
	repl := caddy.NewReplacer()

	client, err := hl.makeClient(ctx)
	if err != nil {
		return nil, err
	}

	method := repl.ReplaceAll(hl.Method, "")
	if method == "" {
		method = http.MethodGet
	}

	url := repl.ReplaceAll(hl.URL, "")
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	for key, vals := range hl.Headers {
		for _, val := range vals {
			req.Header.Add(repl.ReplaceAll(key, ""), repl.ReplaceKnown(val, ""))
		}
	}

	resp, err := doHttpCallWithRetries(ctx, client, req, hl.RetryDelay)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server responded with HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result, warnings, err := adaptByContentType(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, err
	}
	for _, warn := range warnings {
		ctx.Logger().Warn(warn.String())
	}

	return result, nil
}

// Reattempts the http call, waiting `retryDelay` seconds in between attempts.
func doHttpCallWithRetries(ctx caddy.Context, client *http.Client, request *http.Request, retryDelay time.Duration) (*http.Response, error) {
	// make attempt
	resp, err := client.Do(request)
	if err != nil {
		err = fmt.Errorf("problem calling http loader url: %v", err)
	} else if resp.StatusCode < 200 || resp.StatusCode > 499 {
		err = fmt.Errorf("bad response status code from http loader url: %v", resp.StatusCode)
	} else {
		return resp, nil
	}
	// skip retries if valid retryDelay not provided
	if retryDelay <= 0 {
		return resp, err
	}
	// log the error
	caddy.Log().Error(err.Error())
	// wait for the retry delay to lapse before reattempting,
	// or return when context is done
	select {
	case <-time.After(time.Second * retryDelay):
		return doHttpCallWithRetries(ctx, client, request, retryDelay)
	case <-ctx.Done():
		return nil, err
	}
}

func (hl HTTPLoader) makeClient(ctx caddy.Context) (*http.Client, error) {
	client := &http.Client{
		Timeout: time.Duration(hl.Timeout),
	}

	if hl.TLS != nil {
		var tlsConfig *tls.Config

		// client authentication
		if hl.TLS.UseServerIdentity {
			certs, err := ctx.IdentityCredentials(ctx.Logger())
			if err != nil {
				return nil, fmt.Errorf("getting server identity credentials: %v", err)
			}
			if tlsConfig == nil {
				tlsConfig = new(tls.Config)
			}
			tlsConfig.Certificates = certs
		} else if hl.TLS.ClientCertificateFile != "" && hl.TLS.ClientCertificateKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(hl.TLS.ClientCertificateFile, hl.TLS.ClientCertificateKeyFile)
			if err != nil {
				return nil, err
			}
			if tlsConfig == nil {
				tlsConfig = new(tls.Config)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// trusted server certs
		if len(hl.TLS.RootCAPEMFiles) > 0 {
			rootPool := x509.NewCertPool()
			for _, pemFile := range hl.TLS.RootCAPEMFiles {
				pemData, err := os.ReadFile(pemFile)
				if err != nil {
					return nil, fmt.Errorf("failed reading ca cert: %v", err)
				}
				rootPool.AppendCertsFromPEM(pemData)
			}
			if tlsConfig == nil {
				tlsConfig = new(tls.Config)
			}
			tlsConfig.RootCAs = rootPool
		}

		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	return client, nil
}

var _ caddy.ConfigLoader = (*HTTPLoader)(nil)
