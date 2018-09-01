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

// +build dev

// build.go automates proper versioning of caddy binaries.
// Use it like:   go run build.go
// You can customize the build with the -goos, -goarch, and
// -goarm CLI options:   go run build.go -goos=windows
//
// To get proper version information, this program must be
// run from the directory of this file, and the source code
// must be a working git repository, since it needs to know
// if the source is in a clean state.
//
// This program is NOT required to build Caddy from source
// since it is go-gettable. (You can run plain `go build`
// in this directory to get a binary.) However, issues filed
// without version information will likely be closed.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/caddyserver/builds"
)

var goos, goarch, goarm string

func init() {
	flag.StringVar(&goos, "goos", "", "GOOS for which to build")
	flag.StringVar(&goarch, "goarch", "", "GOARCH for which to build")
	flag.StringVar(&goarm, "goarm", "", "GOARM for which to build")
}

func main() {
	flag.Parse()

	gopath := os.Getenv("GOPATH")

	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	ldflags, err := builds.MakeLdFlags(filepath.Join(pwd, ".."))
	if err != nil {
		log.Fatal(err)
	}

	args := []string{"build", "-ldflags", ldflags}
	args = append(args, "-asmflags", fmt.Sprintf("-trimpath=%s", gopath))
	args = append(args, "-gcflags", fmt.Sprintf("-trimpath=%s", gopath))
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Env = os.Environ()
	for _, env := range []string{
		"CGO_ENABLED=0",
		"GOOS=" + goos,
		"GOARCH=" + goarch,
		"GOARM=" + goarm,
	} {
		cmd.Env = append(cmd.Env, env)
	}

	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}
