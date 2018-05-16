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

package caddymain

import (
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/mholt/caddy"
)

func TestSetCPU(t *testing.T) {
	currentCPU := runtime.GOMAXPROCS(-1)
	maxCPU := runtime.NumCPU()
	halfCPU := int(0.5 * float32(maxCPU))
	if halfCPU < 1 {
		halfCPU = 1
	}
	for i, test := range []struct {
		input     string
		output    int
		shouldErr bool
	}{
		{"1", 1, false},
		{"-1", currentCPU, true},
		{"0", currentCPU, true},
		{"100%", maxCPU, false},
		{"50%", halfCPU, false},
		{"110%", currentCPU, true},
		{"-10%", currentCPU, true},
		{"invalid input", currentCPU, true},
		{"invalid input%", currentCPU, true},
		{"9999", maxCPU, false}, // over available CPU
		{"1%", 1, false},        // under a single CPU; assume maxCPU < 100
	} {
		err := setCPU(test.input)
		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected error, but there wasn't any", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but there was one: %v", i, err)
		}
		if actual, expected := runtime.GOMAXPROCS(-1), test.output; actual != expected {
			t.Errorf("Test %d: GOMAXPROCS was %d but expected %d", i, actual, expected)
		}
		// teardown
		runtime.GOMAXPROCS(currentCPU)
	}
}

func TestCaddyStartStop(t *testing.T) {
	caddyfile := "localhost:1984"

	for i := 0; i < 2; i++ {
		testInst, err := caddy.Start(caddy.CaddyfileInput{Contents: []byte(caddyfile)})
		if err != nil {
			t.Fatalf("Error starting, iteration %d: %v", i, err)
		}

		client := http.Client{
			Timeout: time.Duration(1 * time.Second),
		}
		resp, err := client.Get("http://localhost:1984")
		if err != nil {
			t.Fatalf("Expected GET request to succeed (iteration %d), but it failed: %v", i, err)
		}
		resp.Body.Close()

		err = testInst.Stop()
		if err != nil {
			t.Fatalf("Error stopping, iteration %d: %v", i, err)
		}
		time.Sleep(1)
	}
}
