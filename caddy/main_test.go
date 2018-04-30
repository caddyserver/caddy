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

package main

import "testing"

// This works because it does not have the same signature as the
// conventional "TestMain" function described in the testing package
// godoc.
func TestMain(t *testing.T) {
	var ran bool
	run = func() {
		ran = true
	}
	main()
	if !ran {
		t.Error("Expected Run() to be called, but it wasn't")
	}
}
