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

package caddyauth

import (
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "hash-password",
		Func:  cmdHashPassword,
		Usage: "--plaintext <password> [--salt <string>] [--algorithm <name>]",
		Short: "Hashes a password and writes base64",
		Long: `
Convenient way to hash a plaintext password. The resulting
hash is written to stdout as a base64 string.

--algorithm may be bcrypt or scrypt. If script, the default
parameters are used.

Use the --salt flag for algorithms which require a salt to
be provided (scrypt).
`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("hash-password", flag.ExitOnError)
			fs.String("algorithm", "bcrypt", "Name of the hash algorithm")
			fs.String("plaintext", "", "The plaintext password")
			fs.String("salt", "", "The password salt")
			return fs
		}(),
	})
}

func cmdHashPassword(fs caddycmd.Flags) (int, error) {
	algorithm := fs.String("algorithm")
	plaintext := []byte(fs.String("plaintext"))
	salt := []byte(fs.String("salt"))

	if len(plaintext) == 0 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("password is required")
	}

	var hash []byte
	var err error
	switch algorithm {
	case "bcrypt":
		hash, err = bcrypt.GenerateFromPassword(plaintext, bcrypt.DefaultCost)
	case "scrypt":
		def := ScryptHash{}
		def.SetDefaults()
		hash, err = scrypt.Key(plaintext, salt, def.N, def.R, def.P, def.KeyLength)
	default:
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unrecognized hash algorithm: %s", algorithm)
	}
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	hashBase64 := base64.StdEncoding.EncodeToString(hash)

	fmt.Println(hashBase64)

	return 0, nil
}
