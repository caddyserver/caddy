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

package caddy

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/mholt/caddy/caddyfile"
)

/*
// TODO
func TestCaddyStartStop(t *testing.T) {
	caddyfile := "localhost:1984"

	for i := 0; i < 2; i++ {
		_, err := Start(CaddyfileInput{Contents: []byte(caddyfile)})
		if err != nil {
			t.Fatalf("Error starting, iteration %d: %v", i, err)
		}

		client := http.Client{
			Timeout: time.Duration(2 * time.Second),
		}
		resp, err := client.Get("http://localhost:1984")
		if err != nil {
			t.Fatalf("Expected GET request to succeed (iteration %d), but it failed: %v", i, err)
		}
		resp.Body.Close()

		err = Stop()
		if err != nil {
			t.Fatalf("Error stopping, iteration %d: %v", i, err)
		}
	}
}
*/

// CallbackTestContext implements Context interface
type CallbackTestContext struct {
	// If MakeServersFail is set to true then MakeServers returns an error
	MakeServersFail bool
}

func (h *CallbackTestContext) InspectServerBlocks(name string, sblock []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	return sblock, nil
}
func (h *CallbackTestContext) MakeServers() ([]Server, error) {
	if h.MakeServersFail {
		return make([]Server, 0), fmt.Errorf("MakeServers failed")
	}
	return make([]Server, 0), nil
}

func TestCaddyRestartCallbacks(t *testing.T) {
	for i, test := range []struct {
		restartFail   bool
		expectedCalls []string
	}{
		{false, []string{"OnRestart", "OnShutdown"}},
		{true, []string{"OnRestart", "OnRestartFailed"}},
	} {
		serverName := fmt.Sprintf("%v", i)
		// RegisterServerType to make successful restart possible
		RegisterServerType(serverName, ServerType{
			Directives: func() []string { return []string{} },
			// If MakeServersFail is true then the restart will fail due to context failure
			NewContext: func(inst *Instance) Context { return &CallbackTestContext{MakeServersFail: test.restartFail} },
		})
		c := NewTestController(serverName, "")
		c.instance = &Instance{
			serverType: serverName,
			wg:         new(sync.WaitGroup),
		}

		// Register callbacks which save the calls order
		calls := make([]string, 0)
		c.OnRestart(func() error {
			calls = append(calls, "OnRestart")
			return nil
		})
		c.OnRestartFailed(func() error {
			calls = append(calls, "OnRestartFailed")
			return nil
		})
		c.OnShutdown(func() error {
			calls = append(calls, "OnShutdown")
			return nil
		})

		c.instance.Restart(CaddyfileInput{Contents: []byte(""), ServerTypeName: serverName})

		if !reflect.DeepEqual(calls, test.expectedCalls) {
			t.Errorf("Test %d: Callbacks expected: %v, got: %v", i, test.expectedCalls, calls)
		}

		c.instance.Stop()
		c.instance.Wait()
	}

}

func TestIsLoopback(t *testing.T) {
	for i, test := range []struct {
		input  string
		expect bool
	}{
		{"example.com", false},
		{"localhost", true},
		{"localhost:1234", true},
		{"localhost:", true},
		{"127.0.0.1", true},
		{"127.0.0.1:443", true},
		{"127.0.1.5", true},
		{"10.0.0.5", false},
		{"12.7.0.1", false},
		{"[::1]", true},
		{"[::1]:1234", true},
		{"::1", true},
		{"::", false},
		{"[::]", false},
		{"local", false},
	} {
		if got, want := IsLoopback(test.input), test.expect; got != want {
			t.Errorf("Test %d (%s): expected %v but was %v", i, test.input, want, got)
		}
	}
}

func TestIsInternal(t *testing.T) {
	for i, test := range []struct {
		input  string
		expect bool
	}{
		{"9.255.255.255", false},
		{"10.0.0.0", true},
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"10.255.255.255", true},
		{"11.0.0.0", false},
		{"10.0.0.5:1234", true},
		{"11.0.0.5:1234", false},

		{"172.15.255.255", false},
		{"172.16.0.0", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"172.31.255.255", true},
		{"172.32.0.0", false},
		{"172.16.0.1:1234", true},

		{"192.167.255.255", false},
		{"192.168.0.0", true},
		{"192.168.0.1", true},
		{"192.168.255.254", true},
		{"192.168.255.255", true},
		{"192.169.0.0", false},
		{"192.168.0.1:1234", true},

		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"fc00::", true},
		{"fc00::1", true},
		{"[fc00::1]", true},
		{"[fc00::1]:8888", true},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", true},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"fe00::", false},
		{"fd12:3456:789a:1::1:1234", true},

		{"example.com", false},
		{"localhost", false},
		{"localhost:1234", false},
		{"localhost:", false},
		{"127.0.0.1", false},
		{"127.0.0.1:443", false},
		{"127.0.1.5", false},
		{"12.7.0.1", false},
		{"[::1]", false},
		{"[::1]:1234", false},
		{"::1", false},
		{"::", false},
		{"[::]", false},
		{"local", false},
	} {
		if got, want := IsInternal(test.input), test.expect; got != want {
			t.Errorf("Test %d (%s): expected %v but was %v", i, test.input, want, got)
		}
	}
}

func TestListenerAddrEqual(t *testing.T) {
	ln1, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()
	ln1port := strconv.Itoa(ln1.Addr().(*net.TCPAddr).Port)

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	ln2port := strconv.Itoa(ln2.Addr().(*net.TCPAddr).Port)

	for i, test := range []struct {
		ln     net.Listener
		addr   string
		expect bool
	}{
		{ln1, ":" + ln2port, false},
		{ln1, "0.0.0.0:" + ln2port, false},
		{ln1, "0.0.0.0", false},
		{ln1, ":" + ln1port, true},
		{ln1, "0.0.0.0:" + ln1port, true},
		{ln2, ":" + ln2port, false},
		{ln2, "127.0.0.1:" + ln1port, false},
		{ln2, "127.0.0.1", false},
		{ln2, "127.0.0.1:" + ln2port, true},
	} {
		if got, want := listenerAddrEqual(test.ln, test.addr), test.expect; got != want {
			t.Errorf("Test %d (%s == %s): expected %v but was %v", i, test.addr, test.ln.Addr().String(), want, got)
		}
	}
}
