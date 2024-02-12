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
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "hash-password",
		Usage: "[--plaintext <password>] [--algorithm <name>]",
		Short: "Hashes a password and writes base64",
		Long: `
Convenient way to hash a plaintext password. The resulting
hash is written to stdout as a base64 string.

--plaintext, when omitted, will be read from stdin. If
Caddy is attached to a controlling tty, the plaintext will
not be echoed.

--algorithm currently only supports 'bcrypt', and is the default.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("plaintext", "p", "", "The plaintext password")
			cmd.Flags().StringP("algorithm", "a", "bcrypt", "Name of the hash algorithm")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdHashPassword)
		},
	})
}

func cmdHashPassword(fs caddycmd.Flags) (int, error) {
	var err error

	algorithm := fs.String("algorithm")
	plaintext := []byte(fs.String("plaintext"))

	if len(plaintext) == 0 {
		fd := int(os.Stdin.Fd())
		if term.IsTerminal(fd) {
			// ensure the terminal state is restored on SIGINT
			state, _ := term.GetState(fd)
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			go func() {
				<-c
				_ = term.Restore(fd, state)
				os.Exit(caddy.ExitCodeFailedStartup)
			}()
			defer signal.Stop(c)

			fmt.Fprint(os.Stderr, "Enter password: ")
			plaintext, err = term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return caddy.ExitCodeFailedStartup, err
			}

			fmt.Fprint(os.Stderr, "Confirm password: ")
			confirmation, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return caddy.ExitCodeFailedStartup, err
			}

			if !bytes.Equal(plaintext, confirmation) {
				return caddy.ExitCodeFailedStartup, fmt.Errorf("password does not match")
			}
		} else {
			rd := bufio.NewReader(os.Stdin)
			plaintext, err = rd.ReadBytes('\n')
			if err != nil {
				return caddy.ExitCodeFailedStartup, err
			}

			plaintext = plaintext[:len(plaintext)-1] // Trailing newline
		}

		if len(plaintext) == 0 {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("plaintext is required")
		}
	}

	var hash []byte
	var hashString string
	switch algorithm {
	case "bcrypt":
		hash, err = BcryptHash{}.Hash(plaintext)
		hashString = string(hash)
	default:
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unrecognized hash algorithm: %s", algorithm)
	}
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	fmt.Println(hashString)

	return 0, nil
}
