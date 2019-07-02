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
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/certmagic"
	"github.com/mitchellh/go-ps"
)

func cmdStart() (int, error) {
	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	startCmdConfigFlag := startCmd.String("config", "", "Configuration file")
	startCmd.Parse(os.Args[2:])

	// open a listener to which the child process will connect when
	// it is ready to confirm that it has successfully started
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 1, fmt.Errorf("opening listener for success confirmation: %v", err)
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
	stdinpipe, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("creating stdin pipe: %v", err)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// generate the random bytes we'll send to the child process
	expect := make([]byte, 32)
	_, err = rand.Read(expect)
	if err != nil {
		return 1, fmt.Errorf("generating random confirmation bytes: %v", err)
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
		return 1, fmt.Errorf("starting caddy process: %v", err)
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
				log.Println(err)
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
		err = cmd.Wait() // don't send on this line! Wait blocks, but send starts before it unblocks
		exit <- err      // sending on separate line ensures select won't trigger until after Wait unblocks
	}()

	// when one of the goroutines unblocks, we're done and can exit
	select {
	case <-success:
		fmt.Println("Successfully started Caddy")
	case err := <-exit:
		return 1, fmt.Errorf("caddy process exited with error: %v", err)
	}

	return 0, nil
}

func cmdRun() (int, error) {
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runCmdConfigFlag := runCmd.String("config", "", "Configuration file")
	runCmdPingbackFlag := runCmd.String("pingback", "", "Echo confirmation bytes to this address on success")
	runCmd.Parse(os.Args[2:])

	// if a config file was specified for bootstrapping
	// the server instance, load it now
	var config []byte
	if *runCmdConfigFlag != "" {
		var err error
		config, err = ioutil.ReadFile(*runCmdConfigFlag)
		if err != nil {
			return 1, fmt.Errorf("reading config file: %v", err)
		}
	}

	// set a fitting User-Agent for ACME requests
	goModule := caddy.GoModule()
	cleanModVersion := strings.TrimPrefix(goModule.Version, "v")
	certmagic.UserAgent = "Caddy/" + cleanModVersion

	// start the admin endpoint along with any initial config
	err := caddy.StartAdmin(config)
	if err != nil {
		return 0, fmt.Errorf("starting caddy administration endpoint: %v", err)
	}
	defer caddy.StopAdmin()

	// if we are to report to another process the successful start
	// of the server, do so now by echoing back contents of stdin
	if *runCmdPingbackFlag != "" {
		confirmationBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return 1, fmt.Errorf("reading confirmation bytes from stdin: %v", err)
		}
		conn, err := net.Dial("tcp", *runCmdPingbackFlag)
		if err != nil {
			return 1, fmt.Errorf("dialing confirmation address: %v", err)
		}
		defer conn.Close()
		_, err = conn.Write(confirmationBytes)
		if err != nil {
			return 1, fmt.Errorf("writing confirmation bytes to %s: %v", *runCmdPingbackFlag, err)
		}
	}

	select {}
}

func cmdStop() (int, error) {
	processList, err := ps.Processes()
	if err != nil {
		return 1, fmt.Errorf("listing processes: %v", err)
	}
	thisProcName := filepath.Base(os.Args[0])
	var found bool
	for _, p := range processList {
		// the process we're looking for should have the same name but different PID
		if p.Executable() == thisProcName && p.Pid() != os.Getpid() {
			found = true
			fmt.Printf("pid=%d\n", p.Pid())
			fmt.Printf("Graceful stop...")
			if err := gracefullyStopProcess(p.Pid()); err != nil {
				return 1, err
			}
		}
	}
	if !found {
		return 1, fmt.Errorf("Caddy is not running")
	}
	fmt.Println(" success")
	return 0, nil
}

func cmdVersion() (int, error) {
	goModule := caddy.GoModule()
	if goModule.Sum != "" {
		// a build with a known version will also have a checksum
		fmt.Printf("%s %s\n", goModule.Version, goModule.Sum)
	} else {
		fmt.Println(goModule.Version)
	}
	return 0, nil
}

func cmdListModules() (int, error) {
	for _, m := range caddy.Modules() {
		fmt.Println(m)
	}
	return 0, nil
}

func cmdEnviron() (int, error) {
	for _, v := range os.Environ() {
		fmt.Println(v)
	}
	return 0, nil
}
