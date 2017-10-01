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

package httpserver

import (
	"fmt"
)

var (
	_ error = NonHijackerError{}
	_ error = NonFlusherError{}
	_ error = NonCloseNotifierError{}
	_ error = NonPusherError{}
)

// NonHijackerError is more descriptive error caused by a non hijacker
type NonHijackerError struct {
	// underlying type which doesn't implement Hijack
	Underlying interface{}
}

// Implement Error
func (h NonHijackerError) Error() string {
	return fmt.Sprintf("%T is not a hijacker", h.Underlying)
}

// NonFlusherError is more descriptive error caused by a non flusher
type NonFlusherError struct {
	// underlying type which doesn't implement Flush
	Underlying interface{}
}

// Implement Error
func (f NonFlusherError) Error() string {
	return fmt.Sprintf("%T is not a flusher", f.Underlying)
}

// NonCloseNotifierError is more descriptive error caused by a non closeNotifier
type NonCloseNotifierError struct {
	// underlying type which doesn't implement CloseNotify
	Underlying interface{}
}

// Implement Error
func (c NonCloseNotifierError) Error() string {
	return fmt.Sprintf("%T is not a closeNotifier", c.Underlying)
}

// NonPusherError is more descriptive error caused by a non pusher
type NonPusherError struct {
	// underlying type which doesn't implement pusher
	Underlying interface{}
}

// Implement Error
func (c NonPusherError) Error() string {
	return fmt.Sprintf("%T is not a pusher", c.Underlying)
}
