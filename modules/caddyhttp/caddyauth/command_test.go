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
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/bcrypt"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func TestHashPasswordFromStdin(t *testing.T) {
	for _, algorithm := range []string{bcryptName, argon2idName} {
		for _, tc := range []struct{ input, password string }{
			{"secret\n", "secret"},
			{"secret\r\n", "secret"},
			{"secret", "secret"},
			{"secret\r", "secret\r"}, // no line ending, so the \r is part of the password
		} {
			name := algorithm + "/" + strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(tc.input)
			t.Run(name, func(t *testing.T) {
				hash := hashPasswordWithStdin(t, algorithm, tc.input)
				var ok bool
				var err error
				if algorithm == bcryptName {
					ok, err = BcryptHash{}.Compare([]byte(hash), []byte(tc.password))
				} else {
					ok, err = Argon2idHash{}.Compare([]byte(hash), []byte(tc.password))
				}
				if err != nil || !ok {
					t.Fatalf("hash %q does not match the password (err: %v)", hash, err)
				}
			})
		}
	}
}

// hashPasswordWithStdin runs the hash-password command with input
// piped to stdin and returns what it wrote to stdout.
func hashPasswordWithStdin(t *testing.T, algorithm, input string) string {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdinR, stdoutW
	defer func() { os.Stdin, os.Stdout = origStdin, origStdout }()

	if _, err := stdinW.WriteString(input); err != nil {
		t.Fatal(err)
	}
	stdinW.Close()

	fs := pflag.NewFlagSet("hash-password", pflag.ContinueOnError)
	fs.String("plaintext", "", "")
	fs.String("algorithm", algorithm, "")
	fs.Int("bcrypt-cost", bcrypt.MinCost, "")
	fs.Uint32("argon2id-time", defaultArgon2idTime, "")
	fs.Uint32("argon2id-memory", defaultArgon2idMemory, "")
	fs.Uint8("argon2id-threads", defaultArgon2idThreads, "")
	fs.Uint32("argon2id-keylen", defaultArgon2idKeylen, "")

	code, err := cmdHashPassword(caddycmd.Flags{FlagSet: fs})
	stdoutW.Close()
	if err != nil {
		t.Fatalf("hash-password failed (exit code %d): %v", code, err)
	}

	out, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
