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
	"github.com/mholt/caddy/caddyhttp/httpserver"
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
	c := caddy.NewTestController("http", "index a.html b.html c.html")

	err := setupIndex(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	expectedIndex := []string{"a.html", "b.html", "c.html"}

	siteConfig := httpserver.GetConfig(c)

	if len(siteConfig.IndexPages) != len(expectedIndex) {
		t.Errorf("Expected 3 values, got %v", len(siteConfig.IndexPages))
	}

	// Ensure ordering is correct
	for i, actual := range siteConfig.IndexPages {
		if actual != expectedIndex[i] {
			t.Errorf("Expected value in position %d to be %v, got %v", i, expectedIndex[i], actual)
		}
	}
}

func TestMultiSiteIndexWithEitherHasDefault(t *testing.T) {
	// TestIndex already covers the correctness of the directive
	// when used on a single controller, so no need to verify test setupIndex again.
	// This sets the stage for the actual verification.
	customIndex := caddy.NewTestController("http", "index a.html b.html")

	// setupIndex against customIdx should not pollute the
	// index list for other controllers.
	err := setupIndex(customIndex)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	// Represents a virtual host with no index directive.
	defaultIndex := caddy.NewTestController("http", "")

	// Not calling setupIndex because it guards against lack of arguments,
	// and we need to ensure the site gets the default set of index pages.

	siteConfig := httpserver.GetConfig(defaultIndex)

	// In case the index directive is not used, the virtual host
	// should receive staticfiles.DefaultIndexPages slice. The length, as checked here,
	// and the values, as checked in the upcoming loop, should match.
	if len(siteConfig.IndexPages) != len(staticfiles.DefaultIndexPages) {
		t.Errorf("Expected %d values, got %d", len(staticfiles.DefaultIndexPages), len(siteConfig.IndexPages))
	}

	// Ensure values match the expected default index pages
	for i, actual := range siteConfig.IndexPages {
		if actual != staticfiles.DefaultIndexPages[i] {
			t.Errorf("Expected value in position %d to be %v, got %v", i, staticfiles.DefaultIndexPages[i], actual)
		}
	}
}

func TestPerSiteIndexPageIsolation(t *testing.T) {
	firstIndex := "first.html"
	secondIndex := "second.html"

	// Create two sites with different index page configurations
	firstSite := caddy.NewTestController("http", "index first.html")
	err := setupIndex(firstSite)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	secondSite := caddy.NewTestController("http", "index second.html")
	err = setupIndex(secondSite)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	firstSiteConfig := httpserver.GetConfig(firstSite)
	if firstSiteConfig.IndexPages[0] != firstIndex {
		t.Errorf("Expected index for first site as %s, received %s", firstIndex, firstSiteConfig.IndexPages[0])
	}

	secondSiteConfig := httpserver.GetConfig(secondSite)
	if secondSiteConfig.IndexPages[0] != secondIndex {
		t.Errorf("Expected index for second site as %s, received %s", secondIndex, secondSiteConfig.IndexPages[0])
	}

	// They should have different index pages, as per the provided config.
	if firstSiteConfig.IndexPages[0] == secondSiteConfig.IndexPages[0] {
		t.Errorf("Expected different index pages for both sites, got %s for first and %s for second", firstSiteConfig.IndexPages[0], secondSiteConfig.IndexPages[0])
	}
}
