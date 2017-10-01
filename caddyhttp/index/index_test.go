// Copyright 2015 Light Code Labs, LLC
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

package index

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func TestIndexIncompleteParams(t *testing.T) {
	c := caddy.NewTestController("", "index")

	err := setupIndex(c)
	if err == nil {
		t.Error("Expected an error, but didn't get one")
	}
}

func TestIndex(t *testing.T) {
	c := caddy.NewTestController("", "index a.html b.html c.html")

	err := setupIndex(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	expectedIndex := []string{"a.html", "b.html", "c.html"}

	if len(staticfiles.IndexPages) != 3 {
		t.Errorf("Expected 3 values, got %v", len(staticfiles.IndexPages))
	}

	// Ensure ordering is correct
	for i, actual := range staticfiles.IndexPages {
		if actual != expectedIndex[i] {
			t.Errorf("Expected value in position %d to be %v, got %v", i, expectedIndex[i], actual)
		}
	}
}
