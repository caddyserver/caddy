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
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/certmagic"
	"github.com/smallstep/truststore"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "trust",
		Func:  cmdTrust,
		Short: "Installs a CA certificate into local trust stores",
		Long: `
Adds a root certificate into the local trust stores. Intended for
development environments only.

Since Caddy will install its root certificates into the local trust
stores automatically when they are first generated, this command is
only necessary if you need to pre-install the certificates before
using them; for example, if you have elevated privileges at one
point but not later, you will want to use this command so that a
password prompt is not required later.

This command installs the root certificate only for Caddy's
default CA.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("trust", flag.ExitOnError)
			fs.String("storage", "", "The path to Caddy's storage if not in a default location")
			return fs
		}(),
	})

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "untrust",
		Func:  cmdUntrust,
		Usage: "[--ca <id> | --cert <path>]",
		Short: "Untrusts a locally-trusted CA certificate",
		Long: `
Untrusts a root certificate from the local trust store(s). Intended
for development environments only.

This command uninstalls trust; it does not necessarily delete the
root certificate from trust stores entirely. Thus, repeatedly
trusting and untrusting new certificates can fill up trust databases.

This command does not delete or modify certificate files.

Specify which certificate to untrust either by the ID of its CA with
the --ca flag, or the direct path to the certificate file with the
--cert flag. If the --ca flag is used, only the default storage paths
are assumed (i.e. using --ca flag with custom storage backends or file
paths will not work).

If no flags are specified, --ca=local is assumed.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("untrust", flag.ExitOnError)
			fs.String("ca", "", "The ID of the CA to untrust")
			fs.String("cert", "", "The path to the CA certificate to untrust")
			return fs
		}(),
	})
}

func cmdTrust(fs caddycmd.Flags) (int, error) {
	storagePath := fs.String("storage")

	// we have to create a sort of dummy context so that
	// the CA can provision itself...
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// if no storage path is specified, use the default location
	var storage *certmagic.FileStorage
	if storagePath != "" {
		storage = &certmagic.FileStorage{Path: storagePath}
	} else {
		storage = caddy.DefaultStorage
	}

	// provision the CA, which generates and stores a root
	// certificate if one doesn't already exist in storage
	ca := CA{
		storage: storage,
	}
	err := ca.Provision(ctx, DefaultCAID, caddy.Log())
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	err = ca.installRoot()
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdUntrust(fs caddycmd.Flags) (int, error) {
	ca := fs.String("ca")
	cert := fs.String("cert")

	if ca != "" && cert != "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("conflicting command line arguments")
	}
	if ca == "" && cert == "" {
		ca = DefaultCAID
	}
	if ca != "" {
		cert = filepath.Join(caddy.AppDataDir(), "pki", "authorities", ca, "root.crt")
	}

	// sanity check, make sure cert file exists first
	_, err := os.Stat(cert)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("accessing certificate file: %v", err)
	}

	err = truststore.UninstallFile(cert,
		truststore.WithDebug(),
		truststore.WithFirefox(),
		truststore.WithJava())
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	return caddy.ExitCodeSuccess, nil
}
