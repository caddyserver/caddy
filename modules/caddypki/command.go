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

package caddypki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/smallstep/truststore"
	"github.com/spf13/cobra"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "trust",
		Usage: "[--ca <id>] [--address <listen>] [--config <path> [--adapter <name>]]",
		Short: "Installs a CA certificate into local trust stores",
		Long: `
Adds a root certificate into the local trust stores.

Caddy will attempt to install its root certificates into the local
trust stores automatically when they are first generated, but it
might fail if Caddy doesn't have the appropriate permissions to
write to the trust store. This command is necessary to pre-install
the certificates before using them, if the server process runs as an
unprivileged user (such as via systemd).

By default, this command installs the root certificate for Caddy's
default CA (i.e. 'local'). You may specify the ID of another CA
with the --ca flag.

This command will attempt to connect to Caddy's admin API running at
'` + caddy.DefaultAdminListen + `' to fetch the root certificate. You may
explicitly specify the --address, or use the --config flag to load
the admin address from your config, if not using the default.`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("ca", "", "", "The ID of the CA to trust (defaults to 'local')")
			cmd.Flags().StringP("address", "", "", "Address of the administration API listener (if --config is not used)")
			cmd.Flags().StringP("config", "c", "", "Configuration file (if --address is not used)")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (if --config is used)")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdTrust)
		},
	})

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "untrust",
		Usage: "[--cert <path>] | [[--ca <id>] [--address <listen>] [--config <path> [--adapter <name>]]]",
		Short: "Untrusts a locally-trusted CA certificate",
		Long: `
Untrusts a root certificate from the local trust store(s).

This command uninstalls trust; it does not necessarily delete the
root certificate from trust stores entirely. Thus, repeatedly
trusting and untrusting new certificates can fill up trust databases.

This command does not delete or modify certificate files from Caddy's
configured storage.

This command can be used in one of two ways. Either by specifying
which certificate to untrust by a direct path to the certificate
file with the --cert flag, or by fetching the root certificate for
the CA from the admin API (default behaviour).

If the admin API is used, then the CA defaults to 'local'. You may
specify the ID of another CA with the --ca flag. By default, this
will attempt to connect to the Caddy's admin API running at
'` + caddy.DefaultAdminListen + `' to fetch the root certificate.
You may explicitly specify the --address, or use the --config flag
to load the admin address from your config, if not using the default.`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("cert", "p", "", "The path to the CA certificate to untrust")
			cmd.Flags().StringP("ca", "", "", "The ID of the CA to untrust (defaults to 'local')")
			cmd.Flags().StringP("address", "", "", "Address of the administration API listener (if --config is not used)")
			cmd.Flags().StringP("config", "c", "", "Configuration file (if --address is not used)")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (if --config is used)")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdUntrust)
		},
	})
}

func cmdTrust(fl caddycmd.Flags) (int, error) {
	caID := fl.String("ca")
	addrFlag := fl.String("address")
	configFlag := fl.String("config")
	configAdapterFlag := fl.String("adapter")

	// Prepare the URI to the admin endpoint
	if caID == "" {
		caID = DefaultCAID
	}

	// Determine where we're sending the request to get the CA info
	adminAddr, err := caddycmd.DetermineAdminAPIAddress(addrFlag, nil, configFlag, configAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("couldn't determine admin API address: %v", err)
	}

	// Fetch the root cert from the admin API
	rootCert, err := rootCertFromAdmin(adminAddr, caID)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// Set up the CA struct; we only need to fill in the root
	// because we're only using it to make use of the installRoot()
	// function. Also needs a logger for warnings, and a "cert path"
	// for the root cert; since we're loading from the API and we
	// don't know the actual storage path via this flow, we'll just
	// pass through the admin API address instead.
	ca := CA{
		log:          caddy.Log(),
		root:         rootCert,
		rootCertPath: adminAddr + path.Join(adminPKIEndpointBase, "ca", caID),
	}

	// Install the cert!
	err = ca.installRoot()
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdUntrust(fl caddycmd.Flags) (int, error) {
	certFile := fl.String("cert")
	caID := fl.String("ca")
	addrFlag := fl.String("address")
	configFlag := fl.String("config")
	configAdapterFlag := fl.String("adapter")

	if certFile != "" && (caID != "" || addrFlag != "" || configFlag != "") {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("conflicting command line arguments, cannot use --cert with other flags")
	}

	// If a file was specified, try to uninstall the cert matching that file
	if certFile != "" {
		// Sanity check, make sure cert file exists first
		_, err := os.Stat(certFile)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("accessing certificate file: %v", err)
		}

		// Uninstall the file!
		err = truststore.UninstallFile(certFile,
			truststore.WithDebug(),
			truststore.WithFirefox(),
			truststore.WithJava())
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to uninstall certificate file: %v", err)
		}

		return caddy.ExitCodeSuccess, nil
	}

	// Prepare the URI to the admin endpoint
	if caID == "" {
		caID = DefaultCAID
	}

	// Determine where we're sending the request to get the CA info
	adminAddr, err := caddycmd.DetermineAdminAPIAddress(addrFlag, nil, configFlag, configAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("couldn't determine admin API address: %v", err)
	}

	// Fetch the root cert from the admin API
	rootCert, err := rootCertFromAdmin(adminAddr, caID)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// Uninstall the cert!
	err = truststore.Uninstall(rootCert,
		truststore.WithDebug(),
		truststore.WithFirefox(),
		truststore.WithJava())
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to uninstall certificate file: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

// rootCertFromAdmin makes the API request to fetch the root certificate for the named CA via admin API.
func rootCertFromAdmin(adminAddr string, caID string) (*x509.Certificate, error) {
	uri := path.Join(adminPKIEndpointBase, "ca", caID)

	// Make the request to fetch the CA info
	resp, err := caddycmd.AdminAPIRequest(adminAddr, http.MethodGet, uri, make(http.Header), nil)
	if err != nil {
		return nil, fmt.Errorf("requesting CA info: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response
	caInfo := new(caInfo)
	err = json.NewDecoder(resp.Body).Decode(caInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	// Decode the root cert
	rootBlock, _ := pem.Decode([]byte(caInfo.RootCert))
	if rootBlock == nil {
		return nil, fmt.Errorf("failed to decode root certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %v", err)
	}

	return rootCert, nil
}
