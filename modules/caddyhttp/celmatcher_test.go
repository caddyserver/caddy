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

package caddyhttp

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestMatchExpressionProvision(t *testing.T) {
	tests := []struct {
		name       string
		expression *MatchExpression
		wantErr    bool
	}{
		{
			name: "boolean mtaches succeed",
			expression: &MatchExpression{
				Expr: "{http.request.uri.query} != ''",
			},
			wantErr: false,
		},
		{
			name: "reject expressions with non-boolean results",
			expression: &MatchExpression{
				Expr: "{http.request.uri.query}",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.expression.Provision(caddy.Context{}); (err != nil) != tt.wantErr {
				t.Errorf("MatchExpression.Provision() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
