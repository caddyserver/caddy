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

package configbuilder

import (
	"encoding/json"
	"testing"
)

type testApp struct {
	Names []string `json:"names,omitempty"`
}

type otherApp struct{}

func TestGetOrCreateAppSharesAppAcrossCallers(t *testing.T) {
	b := New()

	// two block types contributing to the same app must get the same value
	for _, name := range []string{"a.example.com", "b.example.com"} {
		app, err := GetOrCreateApp(b, "test", func() *testApp { return new(testApp) })
		if err != nil {
			t.Fatalf("GetOrCreateApp: %v", err)
		}
		app.Names = append(app.Names, name)
	}

	var got testApp
	if err := json.Unmarshal(b.Config().AppsRaw["test"], &got); err != nil {
		t.Fatalf("unmarshaling app: %v", err)
	}
	if len(got.Names) != 2 || got.Names[0] != "a.example.com" || got.Names[1] != "b.example.com" {
		t.Errorf("expected both contributions in one app, got %v", got.Names)
	}
}

func TestGetOrCreateAppTypeMismatch(t *testing.T) {
	b := New()
	if err := b.CreateApp("test", new(otherApp)); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if _, err := GetOrCreateApp(b, "test", func() *testApp { return new(testApp) }); err == nil {
		t.Error("expected an error when the existing app has a different type")
	}
}
