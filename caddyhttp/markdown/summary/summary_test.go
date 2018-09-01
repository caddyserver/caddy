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

package summary

import "testing"

func TestMarkdown(t *testing.T) {
	input := []byte(`Testing with just a few words.`)
	got := string(Markdown(input, 3))
	if want := "Testing with just"; want != got {
		t.Errorf("Expected '%s' but got '%s'", want, got)
	}
}
