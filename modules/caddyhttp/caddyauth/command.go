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
		Usage: "[--plaintext <password>] [--algorithm <argon2id|bcrypt>] [--bcrypt-cost <difficulty>] [--argon2id-time <iterations>] [--argon2id-memory <KiB>] [--argon2id-threads <n>] [--argon2id-keylen <bytes>]",
		Short: "Hashes a password and writes base64",
		Long: `
Convenient way to hash a plaintext password. The resulting
hash is written to stdout as a base64 string.

--plaintext
    The password to hash. If omitted, it will be read from stdin.
    If Caddy is attached to a controlling TTY, the input will not be echoed.

--algorithm
    Selects the hashing algorithm. Valid options are:
      * 'argon2id' (recommended for modern security)
      * 'bcrypt'  (legacy, slower, configurable cost)

bcrypt-specific parameters:

--bcrypt-cost
    Sets the bcrypt hashing difficulty. Higher values increase security by
    making the hash computation slower and more CPU-intensive.
    Must be within the valid range [bcrypt.MinCost, bcrypt.MaxCost]. 
    If omitted or invalid, the default cost is used.

Argon2id-specific parameters:

--argon2id-time
    Number of iterations to perform. Increasing this makes
    hashing slower and more resistant to brute-force attacks.

--argon2id-memory
    Amount of memory to use during hashing.
    Larger values increase resistance to GPU/ASIC attacks.

--argon2id-threads
    Number of CPU threads to use. Increase for faster hashing
    on multi-core systems.

--argon2id-keylen
    Length of the resulting hash in bytes. Longer keys increase
    security but slightly increase storage size.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("plaintext", "p", "", "The plaintext password")
			cmd.Flags().StringP("algorithm", "a", bcryptName, "Name of the hash algorithm")
			cmd.Flags().Int("bcrypt-cost", defaultBcryptCost, "Bcrypt hashing cost (only used with 'bcrypt' algorithm)")
			cmd.Flags().Uint32("argon2id-time", defaultArgon2idTime, "Number of iterations for Argon2id hashing. Increasing this makes the hash slower and more resistant to brute-force attacks.")
			cmd.Flags().Uint32("argon2id-memory", defaultArgon2idMemory, "Memory to use in KiB for Argon2id hashing. Larger values increase resistance to GPU/ASIC attacks.")
			cmd.Flags().Uint8("argon2id-threads", defaultArgon2idThreads, "Number of CPU threads to use for Argon2id hashing. Increase for faster hashing on multi-core systems.")
			cmd.Flags().Uint32("argon2id-keylen", defaultArgon2idKeylen, "Length of the resulting Argon2id hash in bytes. Longer hashes increase security but slightly increase storage size.")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdHashPassword)
		},
	})
}

func cmdHashPassword(fs caddycmd.Flags) (int, error) {
	var err error

	algorithm := fs.String("algorithm")
	plaintext := []byte(fs.String("plaintext"))
	bcryptCost := fs.Int("bcrypt-cost")

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
	case bcryptName:
		hash, err = BcryptHash{cost: bcryptCost}.Hash(plaintext)
		hashString = string(hash)
	case argon2idName:
		time, err := fs.GetUint32("argon2id-time")
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to get argon2id time parameter: %w", err)
		}
		memory, err := fs.GetUint32("argon2id-memory")
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to get argon2id memory parameter: %w", err)
		}
		threads, err := fs.GetUint8("argon2id-threads")
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to get argon2id threads parameter: %w", err)
		}
		keyLen, err := fs.GetUint32("argon2id-keylen")
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to get argon2id keylen parameter: %w", err)
		}

		hash, _ = Argon2idHash{
			time:    time,
			memory:  memory,
			threads: threads,
			keyLen:  keyLen,
		}.Hash(plaintext)

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
