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

package reverseproxy

import (
	"context"
	"net"
)

// DialContext connects to the address on the named network using the provided context.
// See net.Dialer for more details.
type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

// ListenerWrapper is a type that wraps a dialer.DialContext method
// so it can modify the input dialer's DialContext method.
// Modules that implement this interface are found
// in the caddy.dial_context_wrappers namespace.
type DialContextWrapper interface {
	WrapDialContext(DialContext) DialContext
}
