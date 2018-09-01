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

package push

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type (
	// Rule describes conditions on which resources will be pushed
	Rule struct {
		Path      string
		Resources []Resource
	}

	// Resource describes resource to be pushed
	Resource struct {
		Path   string
		Method string
		Header http.Header
	}

	// Middleware supports pushing resources to clients
	Middleware struct {
		Next       httpserver.Handler
		Rules      []Rule
		Root       http.FileSystem
		indexPages []string // will be injected from SiteConfig on setup
	}

	ruleOp func([]Resource)
)
