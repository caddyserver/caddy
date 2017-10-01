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

// By moving the application's package main logic into
// a package other than main, it becomes much easier to
// wrap caddy for custom builds that are go-gettable.
// https://caddy.community/t/my-wish-for-0-9-go-gettable-custom-builds/59?u=matt

package main

import "github.com/mholt/caddy/caddy/caddymain"

var run = caddymain.Run // replaced for tests

func main() {
	run()
}
