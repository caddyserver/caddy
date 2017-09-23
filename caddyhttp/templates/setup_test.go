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

package templates

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `templates`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Templates)

	if !ok {
		t.Fatalf("Expected handler to be type Templates, got: %#v", handler)
	}

	if myHandler.Rules[0].Path != defaultTemplatePath {
		t.Errorf("Expected / as the default Path")
	}
	if fmt.Sprint(myHandler.Rules[0].Extensions) != fmt.Sprint(defaultTemplateExtensions) {
		t.Errorf("Expected %v to be the Default Extensions", defaultTemplateExtensions)
	}
	var indexFiles []string
	for _, extension := range defaultTemplateExtensions {
		indexFiles = append(indexFiles, "index"+extension)
	}
	if fmt.Sprint(myHandler.Rules[0].IndexFiles) != fmt.Sprint(indexFiles) {
		t.Errorf("Expected %v to be the Default Index files", indexFiles)
	}
	if myHandler.Rules[0].Delims != [2]string{} {
		t.Errorf("Expected %v to be the Default Delims", [2]string{})
	}
}

func TestTemplatesParse(t *testing.T) {
	tests := []struct {
		inputTemplateConfig    string
		shouldErr              bool
		expectedTemplateConfig []Rule
	}{
		{`templates /api1`, false, []Rule{{
			Path:       "/api1",
			Extensions: defaultTemplateExtensions,
			Delims:     [2]string{},
		}}},
		{`templates /api2 .txt .htm`, false, []Rule{{
			Path:       "/api2",
			Extensions: []string{".txt", ".htm"},
			Delims:     [2]string{},
		}}},

		{`templates /api3 .htm .html
		  templates /api4 .txt .tpl `, false, []Rule{{
			Path:       "/api3",
			Extensions: []string{".htm", ".html"},
			Delims:     [2]string{},
		}, {
			Path:       "/api4",
			Extensions: []string{".txt", ".tpl"},
			Delims:     [2]string{},
		}}},
		{`templates {
				path /api5
				ext .html
				between {% %}
			}`, false, []Rule{{
			Path:       "/api5",
			Extensions: []string{".html"},
			Delims:     [2]string{"{%", "%}"},
		}}},
	}
	for i, test := range tests {
		c := caddy.NewTestController("http", test.inputTemplateConfig)
		actualTemplateConfigs, err := templatesParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualTemplateConfigs) != len(test.expectedTemplateConfig) {
			t.Fatalf("Test %d expected %d no of Template configs, but got %d ",
				i, len(test.expectedTemplateConfig), len(actualTemplateConfigs))
		}
		for j, actualTemplateConfig := range actualTemplateConfigs {
			if actualTemplateConfig.Path != test.expectedTemplateConfig[j].Path {
				t.Errorf("Test %d expected %dth Template Config Path to be  %s  , but got %s",
					i, j, test.expectedTemplateConfig[j].Path, actualTemplateConfig.Path)
			}
			if fmt.Sprint(actualTemplateConfig.Extensions) != fmt.Sprint(test.expectedTemplateConfig[j].Extensions) {
				t.Errorf("Expected %v to be the  Extensions , but got %v instead", test.expectedTemplateConfig[j].Extensions, actualTemplateConfig.Extensions)
			}
		}
	}

}
