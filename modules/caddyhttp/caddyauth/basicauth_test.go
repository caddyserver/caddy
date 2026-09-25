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

func TestBasicAuthRejectsUsernamesThatCollideAfterEnvExpansion(t *testing.T) {
	t.Setenv("X", "carol")
	t.Setenv("Y", "carol")
	t.Setenv("Z", "dave")

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tests := []struct {
		name    string
		users   [2]string
		wantErr bool
	}{
		{name: "literal duplicates", users: [2]string{"carol", "carol"}, wantErr: true},
		{name: "both expanded from env", users: [2]string{"{env.X}", "{env.Y}"}, wantErr: true},
		{name: "literal and expanded", users: [2]string{"carol", "{env.Y}"}, wantErr: true},
		{name: "same placeholder twice", users: [2]string{"{env.X}", "{env.X}"}, wantErr: true},
		{name: "distinct after expansion", users: [2]string{"{env.X}", "{env.Z}"}, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hba := &HTTPBasicAuth{
				AccountList: []Account{
					{Username: tc.users[0], Password: "$2a$04$aaaaaaaaaaaaaaaaaaaaaa"},
					{Username: tc.users[1], Password: "$2a$04$bbbbbbbbbbbbbbbbbbbbbb"},
				},
			}
			err := hba.Provision(ctx)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "username is not unique") {
					t.Fatalf("Provision() = %v, want a username uniqueness error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Provision() = %v", err)
			}
			if len(hba.Accounts) != 2 {
				t.Fatalf("stored %d accounts, want 2", len(hba.Accounts))
			}
		})
	}
}
