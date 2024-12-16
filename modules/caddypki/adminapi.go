// Copyright 2020 Matthew Holt and The Caddy Authors
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

package caddypki

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(adminAPI{})
}

// adminAPI is a module that serves PKI endpoints to retrieve
// information about the CAs being managed by Caddy.
type adminAPI struct {
	ctx    caddy.Context
	log    *zap.Logger
	pkiApp *PKI
}

// CaddyModule returns the Caddy module information.
func (adminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.pki",
		New: func() caddy.Module { return new(adminAPI) },
	}
}

// Provision sets up the adminAPI module.
func (a *adminAPI) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.log = ctx.Logger(a) // TODO: passing in 'a' is a hack until the admin API is officially extensible (see #5032)

	// Avoid initializing PKI if it wasn't configured.
	// We intentionally ignore the error since it's not
	// fatal if the PKI app is not explicitly configured.
	pkiApp, err := ctx.AppIfConfigured("pki")
	if err == nil {
		a.pkiApp = pkiApp.(*PKI)
	}

	return nil
}

// Routes returns the admin routes for the PKI app.
func (a *adminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: adminPKIEndpointBase,
			Handler: caddy.AdminHandlerFunc(a.handleAPIEndpoints),
		},
	}
}

// handleAPIEndpoints routes API requests within adminPKIEndpointBase.
func (a *adminAPI) handleAPIEndpoints(w http.ResponseWriter, r *http.Request) error {
	uri := strings.TrimPrefix(r.URL.Path, "/pki/")
	parts := strings.Split(uri, "/")
	switch {
	case len(parts) == 2 && parts[0] == "ca" && parts[1] != "":
		return a.handleCAInfo(w, r)
	case len(parts) == 3 && parts[0] == "ca" && parts[1] != "" && parts[2] == "certificates":
		return a.handleCACerts(w, r)
	}
	return caddy.APIError{
		HTTPStatus: http.StatusNotFound,
		Err:        fmt.Errorf("resource not found: %v", r.URL.Path),
	}
}

// handleCAInfo returns information about a particular
// CA by its ID. If the CA ID is the default, then the CA will be
// provisioned if it has not already been. Other CA IDs will return an
// error if they have not been previously provisioned.
func (a *adminAPI) handleCAInfo(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed: %v", r.Method),
		}
	}

	ca, err := a.getCAFromAPIRequestPath(r)
	if err != nil {
		return err
	}

	rootCert, interCert, err := rootAndIntermediatePEM(ca)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to get root and intermediate cert for CA %s: %v", ca.ID, err),
		}
	}

	repl := ca.newReplacer()

	response := caInfo{
		ID:               ca.ID,
		Name:             ca.Name,
		RootCN:           repl.ReplaceAll(ca.RootCommonName, ""),
		IntermediateCN:   repl.ReplaceAll(ca.IntermediateCommonName, ""),
		RootCert:         string(rootCert),
		IntermediateCert: string(interCert),
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)

	return nil
}

// handleCACerts returns the certificate chain for a particular
// CA by its ID. If the CA ID is the default, then the CA will be
// provisioned if it has not already been. Other CA IDs will return an
// error if they have not been previously provisioned.
func (a *adminAPI) handleCACerts(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed: %v", r.Method),
		}
	}

	ca, err := a.getCAFromAPIRequestPath(r)
	if err != nil {
		return err
	}

	rootCert, interCert, err := rootAndIntermediatePEM(ca)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to get root and intermediate cert for CA %s: %v", ca.ID, err),
		}
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, err = w.Write(interCert)
	if err == nil {
		_, _ = w.Write(rootCert)
	}

	return nil
}

func (a *adminAPI) getCAFromAPIRequestPath(r *http.Request) (*CA, error) {
	// Grab the CA ID from the request path, it should be the 4th segment (/pki/ca/<ca>)
	id := strings.Split(r.URL.Path, "/")[3]
	if id == "" {
		return nil, caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("missing CA in path"),
		}
	}

	// Find the CA by ID, if PKI is configured
	var ca *CA
	var ok bool
	if a.pkiApp != nil {
		ca, ok = a.pkiApp.CAs[id]
	}

	// If we didn't find the CA, and PKI is not configured
	// then we'll either error out if the CA ID is not the
	// default. If the CA ID is the default, then we'll
	// provision it, because the user probably aims to
	// change their config to enable PKI immediately after
	// if they actually requested the local CA ID.
	if !ok {
		if id != DefaultCAID {
			return nil, caddy.APIError{
				HTTPStatus: http.StatusNotFound,
				Err:        fmt.Errorf("no certificate authority configured with id: %s", id),
			}
		}

		// Provision the default CA, which generates and stores a root
		// certificate in storage, if one doesn't already exist.
		ca = new(CA)
		err := ca.Provision(a.ctx, id, a.log)
		if err != nil {
			return nil, caddy.APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        fmt.Errorf("failed to provision CA %s, %w", id, err),
			}
		}
	}

	return ca, nil
}

func rootAndIntermediatePEM(ca *CA) (root, inter []byte, err error) {
	root, err = pemEncodeCert(ca.RootCertificate().Raw)
	if err != nil {
		return
	}
	inter, err = pemEncodeCert(ca.IntermediateCertificate().Raw)
	if err != nil {
		return
	}
	return
}

// caInfo is the response structure for the CA info API endpoint.
type caInfo struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	RootCN           string `json:"root_common_name"`
	IntermediateCN   string `json:"intermediate_common_name"`
	RootCert         string `json:"root_certificate"`
	IntermediateCert string `json:"intermediate_certificate"`
}

// adminPKIEndpointBase is the base admin endpoint under which all PKI admin endpoints exist.
const adminPKIEndpointBase = "/pki/"

// Interface guards
var (
	_ caddy.AdminRouter = (*adminAPI)(nil)
	_ caddy.Provisioner = (*adminAPI)(nil)
)
