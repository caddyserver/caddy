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

package caddycmd

import (
	// For running in minimal environments, this can ease
	// headaches related to establishing TLS connections.
	// "Package fallback embeds a set of fallback X.509 trusted
	// roots in the application by automatically invoking
	// x509.SetFallbackRoots. This allows the application to
	// work correctly even if the operating system does not
	// provide a verifier or system roots pool. ... It's
	// recommended that only binaries, and not libraries,
	// import this package. This package must be kept up to
	// date for security and compatibility reasons."
	//
	// This is in its own file only because of conflicts
	// between gci and goimports when in main.go.
	// See https://github.com/daixiang0/gci/issues/76
	_ "golang.org/x/crypto/x509roots/fallback"
)
