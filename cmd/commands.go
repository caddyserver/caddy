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
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"

	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/keybase/go-ps"
	"github.com/mholt/certmagic"
)

func cmdStart() (int, error) {
	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	startCmdConfigFlag := startCmd.String("config", "", "Configuration file")
	startCmdConfigAdapterFlag := startCmd.String("config-adapter", "", "Name of config adapter to apply")
	startCmd.Parse(os.Args[2:])

	// open a listener to which the child process will connect when
	// it is ready to confirm that it has successfully started
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("opening listener for success confirmation: %v", err)
	}
	defer ln.Close()

	// craft the command with a pingback address and with a
	// pipe for its stdin, so we can tell it our confirmation
	// code that we expect so that some random port scan at
	// the most unfortunate time won't fool us into thinking
	// the child succeeded (i.e. the alternative is to just
	// wait for any connection on our listener, but better to
	// ensure it's the process we're expecting - we can be
	// sure by giving it some random bytes and having it echo
	// them back to us)
	cmd := exec.Command(os.Args[0], "run", "--pingback", ln.Addr().String())
	if *startCmdConfigFlag != "" {
		cmd.Args = append(cmd.Args, "--config", *startCmdConfigFlag)
	}
	if *startCmdConfigAdapterFlag != "" {
		cmd.Args = append(cmd.Args, "--config-adapter", *startCmdConfigAdapterFlag)
	}
	stdinpipe, err := cmd.StdinPipe()
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("creating stdin pipe: %v", err)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// generate the random bytes we'll send to the child process
	expect := make([]byte, 32)
	_, err = rand.Read(expect)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("generating random confirmation bytes: %v", err)
	}

	// begin writing the confirmation bytes to the child's
	// stdin; use a goroutine since the child hasn't been
	// started yet, and writing sychronously would result
	// in a deadlock
	go func() {
		stdinpipe.Write(expect)
		stdinpipe.Close()
	}()

	// start the process
	err = cmd.Start()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("starting caddy process: %v", err)
	}

	// there are two ways we know we're done: either
	// the process will connect to our listener, or
	// it will exit with an error
	success, exit := make(chan struct{}), make(chan error)

	// in one goroutine, we await the success of the child process
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Println(err)
				}
				break
			}
			err = handlePingbackConn(conn, expect)
			if err == nil {
				close(success)
				break
			}
			log.Println(err)
		}
	}()

	// in another goroutine, we await the failure of the child process
	go func() {
		err := cmd.Wait() // don't send on this line! Wait blocks, but send starts before it unblocks
		exit <- err       // sending on separate line ensures select won't trigger until after Wait unblocks
	}()

	// when one of the goroutines unblocks, we're done and can exit
	select {
	case <-success:
		fmt.Println("Successfully started Caddy")
	case err := <-exit:
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("caddy process exited with error: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdRun() (int, error) {
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runCmdConfigFlag := runCmd.String("config", "", "Configuration file")
	runCmdConfigAdapterFlag := runCmd.String("config-adapter", "", "Name of config adapter to apply")
	runCmdPrintEnvFlag := runCmd.Bool("print-env", false, "Print environment")
	runCmdPingbackFlag := runCmd.String("pingback", "", "Echo confirmation bytes to this address on success")
	runCmd.Parse(os.Args[2:])

	// if we are supposed to print the environment, do that first
	if *runCmdPrintEnvFlag {
		exitCode, err := cmdEnviron()
		if err != nil {
			return exitCode, err
		}
	}

	// get the config in caddy's native format
	config, err := loadConfig(*runCmdConfigFlag, *runCmdConfigAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// set a fitting User-Agent for ACME requests
	goModule := caddy.GoModule()
	cleanModVersion := strings.TrimPrefix(goModule.Version, "v")
	certmagic.UserAgent = "Caddy/" + cleanModVersion

	// start the admin endpoint along with any initial config
	err = caddy.StartAdmin(config)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("starting caddy administration endpoint: %v", err)
	}
	defer caddy.StopAdmin()

	// if we are to report to another process the successful start
	// of the server, do so now by echoing back contents of stdin
	if *runCmdPingbackFlag != "" {
		confirmationBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("reading confirmation bytes from stdin: %v", err)
		}
		conn, err := net.Dial("tcp", *runCmdPingbackFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("dialing confirmation address: %v", err)
		}
		defer conn.Close()
		_, err = conn.Write(confirmationBytes)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("writing confirmation bytes to %s: %v", *runCmdPingbackFlag, err)
		}
	}

	select {}
}

func cmdStop() (int, error) {
	processList, err := ps.Processes()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("listing processes: %v", err)
	}
	thisProcName := getProcessName()
	var found bool
	for _, p := range processList {
		// the process we're looking for should have the same name but different PID
		if p.Executable() == thisProcName && p.Pid() != os.Getpid() {
			found = true
			fmt.Printf("pid=%d\n", p.Pid())

			if err := gracefullyStopProcess(p.Pid()); err != nil {
				return caddy.ExitCodeFailedStartup, err
			}
		}
	}
	if !found {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("Caddy is not running")
	}
	fmt.Println(" success")
	return caddy.ExitCodeSuccess, nil
}

func cmdReload() (int, error) {
	reloadCmd := flag.NewFlagSet("load", flag.ExitOnError)
	reloadCmdConfigFlag := reloadCmd.String("config", "", "Configuration file")
	reloadCmdConfigAdapterFlag := reloadCmd.String("config-adapter", "", "Name of config adapter to apply")
	reloadCmdAddrFlag := reloadCmd.String("address", "", "Address of the administration listener, if different from config")
	reloadCmd.Parse(os.Args[2:])

	// a configuration is required
	if *reloadCmdConfigFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("no configuration to load (use --config)")
	}

	// get the config in caddy's native format
	config, err := loadConfig(*reloadCmdConfigFlag, *reloadCmdConfigAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// get the address of the admin listener and craft endpoint URL
	adminAddr := *reloadCmdAddrFlag
	if adminAddr == "" {
		var tmpStruct struct {
			Admin caddy.AdminConfig `json:"admin"`
		}
		err = json.Unmarshal(config, &tmpStruct)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("unmarshaling admin listener address from config: %v", err)
		}
		adminAddr = tmpStruct.Admin.Listen
	}
	if adminAddr == "" {
		adminAddr = caddy.DefaultAdminListen
	}
	adminEndpoint := fmt.Sprintf("http://%s/load", adminAddr)

	// send the configuration to the instance
	resp, err := http.Post(adminEndpoint, "application/json", bytes.NewReader(config))
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("sending configuration to instance: %v", err)
	}
	defer resp.Body.Close()

	// if it didn't work, let the user know
	if resp.StatusCode >= 400 {
		respBody, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*10))
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("HTTP %d: reading error message: %v", resp.StatusCode, err)
		}
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("caddy responded with error: HTTP %d: %s", resp.StatusCode, respBody)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdVersion() (int, error) {
	goModule := caddy.GoModule()
	if goModule.Sum != "" {
		// a build with a known version will also have a checksum
		fmt.Printf("%s %s\n", goModule.Version, goModule.Sum)
	} else {
		fmt.Println(goModule.Version)
	}
	return caddy.ExitCodeSuccess, nil
}

func cmdListModules() (int, error) {
	for _, m := range caddy.Modules() {
		fmt.Println(m)
	}
	return caddy.ExitCodeSuccess, nil
}

func cmdEnviron() (int, error) {
	for _, v := range os.Environ() {
		fmt.Println(v)
	}
	return caddy.ExitCodeSuccess, nil
}

func cmdAdaptConfig() (int, error) {
	adaptCmd := flag.NewFlagSet("adapt", flag.ExitOnError)
	adaptCmdAdapterFlag := adaptCmd.String("adapter", "", "Name of config adapter")
	adaptCmdInputFlag := adaptCmd.String("input", "", "Configuration file to adapt")
	adaptCmdPrettyFlag := adaptCmd.Bool("pretty", false, "Format the output for human readability")
	adaptCmd.Parse(os.Args[2:])

	if *adaptCmdAdapterFlag == "" || *adaptCmdInputFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("usage: caddy adapt-config --adapter <name> --input <file>")
	}

	cfgAdapter := caddyconfig.GetAdapter(*adaptCmdAdapterFlag)
	if cfgAdapter == nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("unrecognized config adapter: %s", *adaptCmdAdapterFlag)
	}

	input, err := ioutil.ReadFile(*adaptCmdInputFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	opts := make(map[string]interface{})
	if *adaptCmdPrettyFlag {
		opts["pretty"] = "true"
	}

	adaptedConfig, warnings, err := cfgAdapter.Adapt(input, opts)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// print warnings to stderr
	for _, warn := range warnings {
		msg := warn.Message
		if warn.Directive != "" {
			msg = fmt.Sprintf("%s: %s", warn.Directive, warn.Message)
		}
		log.Printf("[WARNING][%s] %s:%d: %s", *adaptCmdAdapterFlag, warn.File, warn.Line, msg)
	}

	// print result to stdout
	fmt.Println(string(adaptedConfig))

	return caddy.ExitCodeSuccess, nil
}
