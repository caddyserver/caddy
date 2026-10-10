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

package caddy

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"

	"github.com/caddyserver/caddy/v2/notify"
)

func init() {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return
	}

	// Windows services always start in the system32 directory, try to
	// switch into the directory where the caddy executable is.
	execPath, err := os.Executable()
	if err == nil {
		_ = os.Chdir(filepath.Dir(execPath))
	}

	go func() {
		_ = svc.Run("", runner{})
	}()
}

// exitOnServiceStop ends the process when the SCM asks the service to
// stop. It is a variable so that the handler can be driven through a stop
// in tests, which cannot afford to exit the test binary.
var exitOnServiceStop = func() { exitProcessFromSignal("SIGINT") }

type runner struct{}

func (runner) Execute(args []string, request <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	// Report StartPending before registering the channel: SetGlobalStatus
	// delivers a status that was requested earlier (Ready, if the config
	// loaded before the SCM called Execute), and that one must come last.
	status <- svc.Status{State: svc.StartPending}
	notify.SetGlobalStatus(status)

	for {
		req := <-request
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			exitOnServiceStop()
			return false, 0
		}
	}
}
