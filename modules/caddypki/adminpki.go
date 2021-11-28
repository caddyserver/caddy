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
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(adminPKI{})
}

// adminPKI is a module that serves a PKI endpoint to retrieve
// information about the CAs being managed by Caddy.
type adminPKI struct {
	ctx    caddy.Context
	log    *zap.Logger
	pkiApp *PKI
}

// CaddyModule returns the Caddy module information.
func (adminPKI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.pki",
		New: func() caddy.Module { return new(adminPKI) },
	}
}

// Provision sets up the adminPKI module.
func (a *adminPKI) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.log = ctx.Logger(a)

	// First check if the PKI app was configured, because
	// a.ctx.App() has the side effect of instantiating
	// and provisioning an app even if it wasn't configured.
	pkiAppConfigured := a.ctx.AppIsConfigured("pki")
	if !pkiAppConfigured {
		return nil
	}

	// Load the PKI app, so we can query it for information.
	appModule, err := a.ctx.App("pki")
	if err != nil {
		return err
	}
	a.pkiApp = appModule.(*PKI)

	return nil
}

// Routes returns the admin routes for the PKI app.
func (a *adminPKI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: amdinPKICertificatesEndpoint,
			Handler: caddy.AdminHandlerFunc(a.handleCertificates),
		},
	}
}

// handleCertificates returns certificate information about a particular
// CA, by its ID. If the CA ID is the default, then the CA will be
// provisioned if it has not already been. Other CA IDs will return an
// error if they have not been previously provisioned.
func (a *adminPKI) handleCertificates(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	// Prep for a JSON response
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)

	idPath := r.URL.Path

	// Grab the CA ID from the request path, it should be the 4th segment
	parts := strings.Split(idPath, "/")
	if len(parts) < 4 || parts[3] == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("request path is missing the CA ID"),
		}
	}
	if parts[0] != "" || parts[1] != "pki" || parts[2] != "certificates" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("malformed object path"),
		}
	}
	id := parts[3]

	// Find the CA by ID, if PKI is configured
	var ca *CA
	ok := false
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
			return caddy.APIError{
				HTTPStatus: http.StatusNotFound,
				Err:        fmt.Errorf("no certificate authority configured with id: %s", id),
			}
		}

		// Provision the default CA, which generates and stores a root
		// certificate in storage, if one doesn't already exist.
		ca = new(CA)
		err := ca.Provision(a.ctx, id, a.log)
		if err != nil {
			return caddy.APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        fmt.Errorf("failed to provision CA %s, %w", id, err),
			}
		}
	}

	// Convert the root certificate to PEM
	rootPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.RootCertificate().Raw,
	}))

	// Convert the intermediate certificate to PEM
	interPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.IntermediateCertificate().Raw,
	}))

	// Build the response
	response := CAInfo{
		Id:           ca.ID,
		Name:         ca.Name,
		Root:         rootPem,
		Intermediate: interPem,
	}

	// Encode and write the JSON response
	err := enc.Encode(response)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}

	return nil
}

// CAInfo is the response from the certificates API endpoint
type CAInfo struct {
	Id           string `json:"id"`
	Name         string `json:"name"`
	Root         string `json:"root"`
	Intermediate string `json:"intermediate"`
}

const amdinPKICertificatesEndpoint = "/pki/certificates/"

// Interface guards
var (
	_ caddy.AdminRouter = (*adminPKI)(nil)
	_ caddy.Provisioner = (*adminPKI)(nil)
)
