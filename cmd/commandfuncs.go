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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/mholt/certmagic"
	"go.uber.org/zap"
)

func cmdStart(fl Flags) (int, error) {
	startCmdConfigFlag := fl.String("config")
	startCmdConfigAdapterFlag := fl.String("adapter")

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
	if startCmdConfigFlag != "" {
		cmd.Args = append(cmd.Args, "--config", startCmdConfigFlag)
	}
	if startCmdConfigAdapterFlag != "" {
		cmd.Args = append(cmd.Args, "--adapter", startCmdConfigAdapterFlag)
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
		fmt.Printf("Successfully started Caddy (pid=%d)\n", cmd.Process.Pid)
	case err := <-exit:
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("caddy process exited with error: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdRun(fl Flags) (int, error) {
	runCmdConfigFlag := fl.String("config")
	runCmdConfigAdapterFlag := fl.String("adapter")
	runCmdResumeFlag := fl.Bool("resume")
	runCmdPrintEnvFlag := fl.Bool("environ")
	runCmdPingbackFlag := fl.String("pingback")

	// if we are supposed to print the environment, do that first
	if runCmdPrintEnvFlag {
		printEnvironment()
	}

	// TODO: This is TEMPORARY, until the RCs
	moveStorage()

	// load the config, depending on flags
	var config []byte
	var err error
	if runCmdResumeFlag {
		config, err = ioutil.ReadFile(caddy.ConfigAutosavePath)
		if os.IsNotExist(err) {
			// not a bad error; just can't resume if autosave file doesn't exist
			caddy.Log().Info("no autosave file exists", zap.String("autosave_file", caddy.ConfigAutosavePath))
			runCmdResumeFlag = false
		} else if err != nil {
			return caddy.ExitCodeFailedStartup, err
		} else {
			caddy.Log().Info("resuming from last configuration", zap.String("autosave_file", caddy.ConfigAutosavePath))
		}
	}
	// we don't use 'else' here since this value might have been changed in 'if' block; i.e. not mutually exclusive
	if !runCmdResumeFlag {
		config, err = loadConfig(runCmdConfigFlag, runCmdConfigAdapterFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
	}

	// set a fitting User-Agent for ACME requests
	goModule := caddy.GoModule()
	cleanModVersion := strings.TrimPrefix(goModule.Version, "v")
	certmagic.UserAgent = "Caddy/" + cleanModVersion

	// run the initial config
	err = caddy.Load(config, true)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("loading initial config: %v", err)
	}
	caddy.Log().Info("serving initial configuration")

	// if we are to report to another process the successful start
	// of the server, do so now by echoing back contents of stdin
	if runCmdPingbackFlag != "" {
		confirmationBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("reading confirmation bytes from stdin: %v", err)
		}
		conn, err := net.Dial("tcp", runCmdPingbackFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("dialing confirmation address: %v", err)
		}
		defer conn.Close()
		_, err = conn.Write(confirmationBytes)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("writing confirmation bytes to %s: %v", runCmdPingbackFlag, err)
		}
	}

	// warn if the environment does not provide enough information about the disk
	hasXDG := os.Getenv("XDG_DATA_HOME") != "" &&
		os.Getenv("XDG_CONFIG_HOME") != "" &&
		os.Getenv("XDG_CACHE_HOME") != ""
	switch runtime.GOOS {
	case "windows":
		if os.Getenv("HOME") == "" && os.Getenv("USERPROFILE") == "" && !hasXDG {
			caddy.Log().Warn("neither HOME nor USERPROFILE environment variables are set - please fix; some assets might be stored in ./caddy")
		}
	case "plan9":
		if os.Getenv("home") == "" && !hasXDG {
			caddy.Log().Warn("$home environment variable is empty - please fix; some assets might be stored in ./caddy")
		}
	default:
		if os.Getenv("HOME") == "" && !hasXDG {
			caddy.Log().Warn("$HOME environment variable is empty - please fix; some assets might be stored in ./caddy")
		}
	}

	select {}
}

func cmdStop(fl Flags) (int, error) {
	stopCmdAddrFlag := fl.String("address")

	adminAddr := caddy.DefaultAdminListen
	if stopCmdAddrFlag != "" {
		adminAddr = stopCmdAddrFlag
	}
	stopEndpoint := fmt.Sprintf("http://%s/stop", adminAddr)

	req, err := http.NewRequest(http.MethodPost, stopEndpoint, nil)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("making request: %v", err)
	}
	req.Header.Set("Origin", adminAddr)

	err = apiRequest(req)
	if err != nil {
		caddy.Log().Warn("failed using API to stop instance",
			zap.String("endpoint", stopEndpoint),
			zap.Error(err),
		)
		return caddy.ExitCodeFailedStartup, err
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdReload(fl Flags) (int, error) {
	reloadCmdConfigFlag := fl.String("config")
	reloadCmdConfigAdapterFlag := fl.String("adapter")
	reloadCmdAddrFlag := fl.String("address")

	// a configuration is required
	if reloadCmdConfigFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("no configuration to load (use --config)")
	}

	// get the config in caddy's native format
	config, err := loadConfig(reloadCmdConfigFlag, reloadCmdConfigAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// get the address of the admin listener and craft endpoint URL
	adminAddr := reloadCmdAddrFlag
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
	loadEndpoint := fmt.Sprintf("http://%s/load", adminAddr)

	// prepare the request to update the configuration
	req, err := http.NewRequest(http.MethodPost, loadEndpoint, bytes.NewReader(config))
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("making request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", adminAddr)

	err = apiRequest(req)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("sending configuration to instance: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdVersion(_ Flags) (int, error) {
	goModule := caddy.GoModule()
	fmt.Print(goModule.Version)
	if goModule.Sum != "" {
		// a build with a known version will also have a checksum
		fmt.Printf(" %s", goModule.Sum)
	}
	if goModule.Replace != nil {
		fmt.Printf(" => %s", goModule.Replace.Path)
		if goModule.Replace.Version != "" {
			fmt.Printf(" %s", goModule.Replace.Version)
		}
	}
	fmt.Println()
	return caddy.ExitCodeSuccess, nil
}

func cmdBuildInfo(fl Flags) (int, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("no build information")
	}

	fmt.Printf("path: %s\n", bi.Path)
	fmt.Printf("main: %s %s %s\n", bi.Main.Path, bi.Main.Version, bi.Main.Sum)
	fmt.Println("dependencies:")

	for _, goMod := range bi.Deps {
		fmt.Printf("%s %s %s", goMod.Path, goMod.Version, goMod.Sum)
		if goMod.Replace != nil {
			fmt.Printf(" => %s %s %s", goMod.Replace.Path, goMod.Replace.Version, goMod.Replace.Sum)
		}
		fmt.Println()
	}
	return caddy.ExitCodeSuccess, nil
}

func cmdListModules(fl Flags) (int, error) {
	versions := fl.Bool("versions")

	bi, ok := debug.ReadBuildInfo()
	if !ok || !versions {
		// if there's no build information,
		// just print out the modules
		for _, m := range caddy.Modules() {
			fmt.Println(m)
		}
		return caddy.ExitCodeSuccess, nil
	}

	for _, modID := range caddy.Modules() {
		modInfo, err := caddy.GetModule(modID)
		if err != nil {
			// that's weird
			fmt.Println(modID)
			continue
		}

		// to get the Caddy plugin's version info, we need to know
		// the package that the Caddy module's value comes from; we
		// can use reflection but we need a non-pointer value (I'm
		// not sure why), and since New() should return a pointer
		// value, we need to dereference it first
		iface := interface{}(modInfo.New())
		if rv := reflect.ValueOf(iface); rv.Kind() == reflect.Ptr {
			iface = reflect.New(reflect.TypeOf(iface).Elem()).Elem().Interface()
		}
		modPkgPath := reflect.TypeOf(iface).PkgPath()

		// now we find the Go module that the Caddy module's package
		// belongs to; we assume the Caddy module package path will
		// be prefixed by its Go module path, and we will choose the
		// longest matching prefix in case there are nested modules
		var matched *debug.Module
		for _, dep := range bi.Deps {
			if strings.HasPrefix(modPkgPath, dep.Path) {
				if matched == nil || len(dep.Path) > len(matched.Path) {
					matched = dep
				}
			}
		}

		// if we could find no matching module, just print out
		// the module ID instead
		if matched == nil {
			fmt.Println(modID)
			continue
		}

		fmt.Printf("%s %s\n", modID, matched.Version)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdEnviron(_ Flags) (int, error) {
	printEnvironment()
	return caddy.ExitCodeSuccess, nil
}

func cmdAdaptConfig(fl Flags) (int, error) {
	adaptCmdInputFlag := fl.String("config")
	adaptCmdAdapterFlag := fl.String("adapter")
	adaptCmdPrettyFlag := fl.Bool("pretty")
	adaptCmdValidateFlag := fl.Bool("validate")

	if adaptCmdAdapterFlag == "" || adaptCmdInputFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("--adapter and --config flags are required")
	}

	cfgAdapter := caddyconfig.GetAdapter(adaptCmdAdapterFlag)
	if cfgAdapter == nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("unrecognized config adapter: %s", adaptCmdAdapterFlag)
	}

	input, err := ioutil.ReadFile(adaptCmdInputFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	opts := make(map[string]interface{})
	if adaptCmdPrettyFlag {
		opts["pretty"] = "true"
	}
	opts["filename"] = adaptCmdInputFlag

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
		fmt.Fprintf(os.Stderr, "[WARNING][%s] %s:%d: %s\n", adaptCmdAdapterFlag, warn.File, warn.Line, msg)
	}

	// print result to stdout
	fmt.Println(string(adaptedConfig))

	// validate output if requested
	if adaptCmdValidateFlag {
		var cfg *caddy.Config
		err = json.Unmarshal(adaptedConfig, &cfg)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("decoding config: %v", err)
		}
		err = caddy.Validate(cfg)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("validation: %v", err)
		}
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdValidateConfig(fl Flags) (int, error) {
	validateCmdConfigFlag := fl.String("config")
	validateCmdAdapterFlag := fl.String("adapter")

	input, err := ioutil.ReadFile(validateCmdConfigFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	if validateCmdAdapterFlag != "" {
		cfgAdapter := caddyconfig.GetAdapter(validateCmdAdapterFlag)
		if cfgAdapter == nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("unrecognized config adapter: %s", validateCmdAdapterFlag)
		}

		adaptedConfig, warnings, err := cfgAdapter.Adapt(input, nil)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
		// print warnings to stderr
		for _, warn := range warnings {
			msg := warn.Message
			if warn.Directive != "" {
				msg = fmt.Sprintf("%s: %s", warn.Directive, warn.Message)
			}
			fmt.Fprintf(os.Stderr, "[WARNING][%s] %s:%d: %s\n", validateCmdAdapterFlag, warn.File, warn.Line, msg)
		}

		input = adaptedConfig
	}

	input = caddy.RemoveMetaFields(input)

	var cfg *caddy.Config
	err = json.Unmarshal(input, &cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("decoding config: %v", err)
	}

	err = caddy.Validate(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	fmt.Println("Valid configuration")

	return caddy.ExitCodeSuccess, nil
}

func cmdHelp(fl Flags) (int, error) {
	const fullDocs = `Full documentation is available at:
https://caddyserver.com/docs/command-line`

	args := fl.Args()
	if len(args) == 0 {
		s := `Caddy is an extensible server platform.

usage:
  caddy <command> [<args...>]

commands:
`
		keys := make([]string, 0, len(commands))
		for k := range commands {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cmd := commands[k]
			short := strings.TrimSuffix(cmd.Short, ".")
			s += fmt.Sprintf("  %-15s %s\n", cmd.Name, short)
		}

		s += "\nUse 'caddy help <command>' for more information about a command.\n"
		s += "\n" + fullDocs + "\n"

		fmt.Print(s)

		return caddy.ExitCodeSuccess, nil
	} else if len(args) > 1 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("can only give help with one command")
	}

	subcommand, ok := commands[args[0]]
	if !ok {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unknown command: %s", args[0])
	}

	helpText := strings.TrimSpace(subcommand.Long)
	if helpText == "" {
		helpText = subcommand.Short
		if !strings.HasSuffix(helpText, ".") {
			helpText += "."
		}
	}

	result := fmt.Sprintf("%s\n\nusage:\n  caddy %s %s\n",
		helpText,
		subcommand.Name,
		strings.TrimSpace(subcommand.Usage),
	)

	if help := flagHelp(subcommand.Flags); help != "" {
		result += fmt.Sprintf("\nflags:\n%s", help)
	}

	result += "\n" + fullDocs + "\n"

	fmt.Print(result)

	return caddy.ExitCodeSuccess, nil
}

func apiRequest(req *http.Request) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("performing request: %v", err)
	}
	defer resp.Body.Close()

	// if it didn't work, let the user know
	if resp.StatusCode >= 400 {
		respBody, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*10))
		if err != nil {
			return fmt.Errorf("HTTP %d: reading error message: %v", resp.StatusCode, err)
		}
		return fmt.Errorf("caddy responded with error: HTTP %d: %s", resp.StatusCode, respBody)
	}

	return nil
}
