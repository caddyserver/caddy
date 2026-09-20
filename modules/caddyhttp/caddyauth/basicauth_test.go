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
	"context"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// testBasicAuthHash is a bcrypt hash (cost 4) of the plaintext "correct horse".
const testBasicAuthHash = "$2a$04$XziKIb5ayw0suaNwlK.1vOqOj9gEveGnkq.anOrdVrnkN5z1bA2A."

func TestBasicAuthProvisionRejectsLiteralDuplicateUsernames(t *testing.T) {
	hba := HTTPBasicAuth{
		AccountList: []Account{
			{Username: "carol", Password: testBasicAuthHash},
			{Username: "carol", Password: testBasicAuthHash},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	err := hba.Provision(ctx)
	if err == nil {
		t.Fatal("expected provisioning to reject literal duplicate usernames")
	}
	if !strings.Contains(err.Error(), "username is not unique") {
		t.Fatalf("expected uniqueness error, got %v", err)
	}
}

func TestBasicAuthProvisionRejectsUsernamesThatCollideAfterEnvExpansion(t *testing.T) {
	t.Setenv("CADDYTEST_BASICAUTH_X", "carol")
	t.Setenv("CADDYTEST_BASICAUTH_Y", "carol")

	cases := []struct {
		name  string
		users []string
	}{
		{"both env", []string{"{env.CADDYTEST_BASICAUTH_X}", "{env.CADDYTEST_BASICAUTH_Y}"}},
		{"literal then env", []string{"carol", "{env.CADDYTEST_BASICAUTH_Y}"}},
		{"same env twice", []string{"{env.CADDYTEST_BASICAUTH_X}", "{env.CADDYTEST_BASICAUTH_X}"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hba := HTTPBasicAuth{
				AccountList: []Account{
					{Username: tc.users[0], Password: testBasicAuthHash},
					{Username: tc.users[1], Password: testBasicAuthHash},
				},
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := hba.Provision(ctx)
			if err == nil {
				t.Fatalf("expected uniqueness error after expansion, got accounts %v", hba.Accounts)
			}
			if !strings.Contains(err.Error(), "username is not unique") {
				t.Fatalf("expected uniqueness error, got %v", err)
			}
			if !strings.Contains(err.Error(), "carol") {
				t.Fatalf("expected expanded username in error, got %v", err)
			}
		})
	}
}

func TestBasicAuthProvisionAllowsDistinctUsernamesAfterEnvExpansion(t *testing.T) {
	t.Setenv("CADDYTEST_BASICAUTH_X", "carol")
	t.Setenv("CADDYTEST_BASICAUTH_Z", "dave")

	hba := HTTPBasicAuth{
		AccountList: []Account{
			{Username: "{env.CADDYTEST_BASICAUTH_X}", Password: testBasicAuthHash},
			{Username: "{env.CADDYTEST_BASICAUTH_Z}", Password: testBasicAuthHash},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := hba.Provision(ctx); err != nil {
		t.Fatalf("provisioning failed: %v", err)
	}
	if len(hba.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d (%v)", len(hba.Accounts), hba.Accounts)
	}
	if _, ok := hba.Accounts["carol"]; !ok {
		t.Fatal("missing carol account")
	}
	if _, ok := hba.Accounts["dave"]; !ok {
		t.Fatal("missing dave account")
	}
}
