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

// bcrypt hashes are stored as-is, so they need no base64 encoding.
const (
	hashOne = "$2a$04$JEsPTnWkE7yxUMxGZBkfUOjvtcDTVI8xmZLmZ2TbEeRpBMkYRGeoO"
	hashTwo = "$2a$04$C5CmKkpmYS8ZCpKnPtBWbOVFQNkHRB5X.8oXpCLXZUhnbEYLkpPpq"
)

func provisionBasicAuth(t *testing.T, accounts []Account) (*HTTPBasicAuth, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	hba := &HTTPBasicAuth{AccountList: accounts}
	return hba, hba.Provision(ctx)
}

// TestProvisionRejectsDuplicateUsernamesAfterPlaceholderExpansion covers usernames
// that are distinct as written but identical once placeholders are expanded. The
// uniqueness check runs on the expanded name, so each of these is rejected; only
// the last account would otherwise survive in the map, silently disabling the others.
func TestProvisionRejectsDuplicateUsernamesAfterPlaceholderExpansion(t *testing.T) {
	t.Setenv("CADDYTEST_USER_A", "carol")
	t.Setenv("CADDYTEST_USER_B", "carol")

	for _, tc := range []struct {
		name     string
		accounts []Account
	}{
		{
			name: "literal duplicates",
			accounts: []Account{
				{Username: "carol", Password: hashOne},
				{Username: "carol", Password: hashTwo},
			},
		},
		{
			name: "two placeholders expanding to the same username",
			accounts: []Account{
				{Username: "{env.CADDYTEST_USER_A}", Password: hashOne},
				{Username: "{env.CADDYTEST_USER_B}", Password: hashTwo},
			},
		},
		{
			name: "literal and placeholder expanding to the same username",
			accounts: []Account{
				{Username: "carol", Password: hashOne},
				{Username: "{env.CADDYTEST_USER_B}", Password: hashTwo},
			},
		},
		{
			name: "same placeholder twice",
			accounts: []Account{
				{Username: "{env.CADDYTEST_USER_A}", Password: hashOne},
				{Username: "{env.CADDYTEST_USER_A}", Password: hashTwo},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provisionBasicAuth(t, tc.accounts)
			if err == nil {
				t.Fatal("expected an error for duplicate usernames, got nil")
			}
			if !strings.Contains(err.Error(), "username is not unique") {
				t.Fatalf("expected a uniqueness error, got: %v", err)
			}
		})
	}
}

// TestProvisionAcceptsDistinctUsernamesFromPlaceholders is the control: placeholders
// that expand to different usernames must still provision both accounts.
func TestProvisionAcceptsDistinctUsernamesFromPlaceholders(t *testing.T) {
	t.Setenv("CADDYTEST_USER_A", "carol")
	t.Setenv("CADDYTEST_USER_C", "dave")

	hba, err := provisionBasicAuth(t, []Account{
		{Username: "{env.CADDYTEST_USER_A}", Password: hashOne},
		{Username: "{env.CADDYTEST_USER_C}", Password: hashTwo},
	})
	if err != nil {
		t.Fatalf("expected distinct usernames to provision, got: %v", err)
	}
	if len(hba.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(hba.Accounts))
	}
	for _, username := range []string{"carol", "dave"} {
		if _, ok := hba.Accounts[username]; !ok {
			t.Errorf("expected an account for %q", username)
		}
	}
}
