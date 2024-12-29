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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/aryann/difflib"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/internal"
)

func cmdStart(fl Flags) (int, error) {
	configFlag := fl.String("config")
	configAdapterFlag := fl.String("adapter")
	pidfileFlag := fl.String("pidfile")
	watchFlag := fl.Bool("watch")

	var err error
	var envfileFlag []string
	envfileFlag, err = fl.GetStringSlice("envfile")
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading envfile flag: %v", err)
	}

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
	// we should be able to run caddy in relative paths
	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}
	if configFlag != "" {
		cmd.Args = append(cmd.Args, "--config", configFlag)
	}

	for _, envfile := range envfileFlag {
		cmd.Args = append(cmd.Args, "--envfile", envfile)
	}
	if configAdapterFlag != "" {
		cmd.Args = append(cmd.Args, "--adapter", configAdapterFlag)
	}
	if watchFlag {
		cmd.Args = append(cmd.Args, "--watch")
	}
	if pidfileFlag != "" {
		cmd.Args = append(cmd.Args, "--pidfile", pidfileFlag)
	}
	stdinPipe, err := cmd.StdinPipe()
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
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("generating random confirmation bytes: %v", err)
	}

	// begin writing the confirmation bytes to the child's
	// stdin; use a goroutine since the child hasn't been
	// started yet, and writing synchronously would result
	// in a deadlock
	go func() {
		_, _ = stdinPipe.Write(expect)
		stdinPipe.Close()
	}()

	// start the process
	err = cmd.Start()
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("starting caddy process: %v", err)
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
				if !errors.Is(err, net.ErrClosed) {
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
		fmt.Printf("Successfully started Caddy (pid=%d) - Caddy is running in the background\n", cmd.Process.Pid)
	case err := <-exit:
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("caddy process exited with error: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdRun(fl Flags) (int, error) {
	caddy.TrapSignals()

	configFlag := fl.String("config")
	configAdapterFlag := fl.String("adapter")
	resumeFlag := fl.Bool("resume")
	printEnvFlag := fl.Bool("environ")
	watchFlag := fl.Bool("watch")
	pidfileFlag := fl.String("pidfile")
	pingbackFlag := fl.String("pingback")

	// load all additional envs as soon as possible
	err := handleEnvFileFlag(fl)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// if we are supposed to print the environment, do that first
	if printEnvFlag {
		printEnvironment()
	}

	// load the config, depending on flags
	var config []byte
	if resumeFlag {
		config, err = os.ReadFile(caddy.ConfigAutosavePath)
		if errors.Is(err, fs.ErrNotExist) {
			// not a bad error; just can't resume if autosave file doesn't exist
			caddy.Log().Info("no autosave file exists", zap.String("autosave_file", caddy.ConfigAutosavePath))
			resumeFlag = false
		} else if err != nil {
			return caddy.ExitCodeFailedStartup, err
		} else {
			if configFlag == "" {
				caddy.Log().Info("resuming from last configuration",
					zap.String("autosave_file", caddy.ConfigAutosavePath))
			} else {
				// if they also specified a config file, user should be aware that we're not
				// using it (doing so could lead to data/config loss by overwriting!)
				caddy.Log().Warn("--config and --resume flags were used together; ignoring --config and resuming from last configuration",
					zap.String("autosave_file", caddy.ConfigAutosavePath))
			}
		}
	}
	// we don't use 'else' here since this value might have been changed in 'if' block; i.e. not mutually exclusive
	var configFile string
	if !resumeFlag {
		config, configFile, err = LoadConfig(configFlag, configAdapterFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
	}

	// create pidfile now, in case loading config takes a while (issue #5477)
	if pidfileFlag != "" {
		err := caddy.PIDFile(pidfileFlag)
		if err != nil {
			caddy.Log().Error("unable to write PID file",
				zap.String("pidfile", pidfileFlag),
				zap.Error(err))
		}
	}

	// run the initial config
	err = caddy.Load(config, true)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("loading initial config: %v", err)
	}
	caddy.Log().Info("serving initial configuration")

	// if we are to report to another process the successful start
	// of the server, do so now by echoing back contents of stdin
	if pingbackFlag != "" {
		confirmationBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("reading confirmation bytes from stdin: %v", err)
		}
		conn, err := net.Dial("tcp", pingbackFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("dialing confirmation address: %v", err)
		}
		defer conn.Close()
		_, err = conn.Write(confirmationBytes)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("writing confirmation bytes to %s: %v", pingbackFlag, err)
		}
	}

	// if enabled, reload config file automatically on changes
	// (this better only be used in dev!)
	if watchFlag {
		go watchConfigFile(configFile, configAdapterFlag)
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
	addressFlag := fl.String("address")
	configFlag := fl.String("config")
	configAdapterFlag := fl.String("adapter")

	adminAddr, err := DetermineAdminAPIAddress(addressFlag, nil, configFlag, configAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("couldn't determine admin API address: %v", err)
	}

	resp, err := AdminAPIRequest(adminAddr, http.MethodPost, "/stop", nil, nil)
	if err != nil {
		caddy.Log().Warn("failed using API to stop instance", zap.Error(err))
		return caddy.ExitCodeFailedStartup, err
	}
	defer resp.Body.Close()

	return caddy.ExitCodeSuccess, nil
}

func cmdReload(fl Flags) (int, error) {
	configFlag := fl.String("config")
	configAdapterFlag := fl.String("adapter")
	addressFlag := fl.String("address")
	forceFlag := fl.Bool("force")

	// get the config in caddy's native format
	config, configFile, err := LoadConfig(configFlag, configAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	if configFile == "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("no config file to load")
	}

	adminAddr, err := DetermineAdminAPIAddress(addressFlag, config, configFlag, configAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("couldn't determine admin API address: %v", err)
	}

	// optionally force a config reload
	headers := make(http.Header)
	if forceFlag {
		headers.Set("Cache-Control", "must-revalidate")
	}

	resp, err := AdminAPIRequest(adminAddr, http.MethodPost, "/load", headers, bytes.NewReader(config))
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("sending configuration to instance: %v", err)
	}
	defer resp.Body.Close()

	return caddy.ExitCodeSuccess, nil
}

func cmdVersion(_ Flags) (int, error) {
	_, full := caddy.Version()
	fmt.Println(full)
	return caddy.ExitCodeSuccess, nil
}

func cmdBuildInfo(_ Flags) (int, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("no build information")
	}
	fmt.Println(bi)
	return caddy.ExitCodeSuccess, nil
}

func cmdListModules(fl Flags) (int, error) {
	packages := fl.Bool("packages")
	versions := fl.Bool("versions")
	skipStandard := fl.Bool("skip-standard")

	printModuleInfo := func(mi moduleInfo) {
		fmt.Print(mi.caddyModuleID)
		if versions && mi.goModule != nil {
			fmt.Print(" " + mi.goModule.Version)
		}
		if packages && mi.goModule != nil {
			fmt.Print(" " + mi.goModule.Path)
			if mi.goModule.Replace != nil {
				fmt.Print(" => " + mi.goModule.Replace.Path)
			}
		}
		if mi.err != nil {
			fmt.Printf(" [%v]", mi.err)
		}
		fmt.Println()
	}

	// organize modules by whether they come with the standard distribution
	standard, nonstandard, unknown, err := getModules()
	if err != nil {
		// oh well, just print the module IDs and exit
		for _, m := range caddy.Modules() {
			fmt.Println(m)
		}
		return caddy.ExitCodeSuccess, nil
	}

	// Standard modules (always shipped with Caddy)
	if !skipStandard {
		if len(standard) > 0 {
			for _, mod := range standard {
				printModuleInfo(mod)
			}
		}
		fmt.Printf("\n  Standard modules: %d\n", len(standard))
	}

	// Non-standard modules (third party plugins)
	if len(nonstandard) > 0 {
		if len(standard) > 0 && !skipStandard {
			fmt.Println()
		}
		for _, mod := range nonstandard {
			printModuleInfo(mod)
		}
	}
	fmt.Printf("\n  Non-standard modules: %d\n", len(nonstandard))

	// Unknown modules (couldn't get Caddy module info)
	if len(unknown) > 0 {
		if (len(standard) > 0 && !skipStandard) || len(nonstandard) > 0 {
			fmt.Println()
		}
		for _, mod := range unknown {
			printModuleInfo(mod)
		}
	}
	fmt.Printf("\n  Unknown modules: %d\n", len(unknown))

	return caddy.ExitCodeSuccess, nil
}

func cmdEnviron(fl Flags) (int, error) {
	// load all additional envs as soon as possible
	err := handleEnvFileFlag(fl)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	printEnvironment()
	return caddy.ExitCodeSuccess, nil
}

func cmdAdaptConfig(fl Flags) (int, error) {
	inputFlag := fl.String("config")
	adapterFlag := fl.String("adapter")
	prettyFlag := fl.Bool("pretty")
	validateFlag := fl.Bool("validate")

	var err error
	inputFlag, err = configFileWithRespectToDefault(caddy.Log(), inputFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// load all additional envs as soon as possible
	err = handleEnvFileFlag(fl)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if adapterFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("adapter name is required (use --adapt flag or leave unspecified for default)")
	}

	cfgAdapter := caddyconfig.GetAdapter(adapterFlag)
	if cfgAdapter == nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("unrecognized config adapter: %s", adapterFlag)
	}

	input, err := os.ReadFile(inputFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	opts := map[string]any{"filename": inputFlag}

	adaptedConfig, warnings, err := cfgAdapter.Adapt(input, opts)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if prettyFlag {
		var prettyBuf bytes.Buffer
		err = json.Indent(&prettyBuf, adaptedConfig, "", "\t")
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
		adaptedConfig = prettyBuf.Bytes()
	}

	// print result to stdout
	fmt.Println(string(adaptedConfig))

	// print warnings to stderr
	for _, warn := range warnings {
		msg := warn.Message
		if warn.Directive != "" {
			msg = fmt.Sprintf("%s: %s", warn.Directive, warn.Message)
		}
		caddy.Log().Named(adapterFlag).Warn(msg,
			zap.String("file", warn.File),
			zap.Int("line", warn.Line))
	}

	// validate output if requested
	if validateFlag {
		var cfg *caddy.Config
		err = caddy.StrictUnmarshalJSON(adaptedConfig, &cfg)
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
	configFlag := fl.String("config")
	adapterFlag := fl.String("adapter")

	// load all additional envs as soon as possible
	err := handleEnvFileFlag(fl)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// use default config and ensure a config file is specified
	configFlag, err = configFileWithRespectToDefault(caddy.Log(), configFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	if configFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("input file required when there is no Caddyfile in current directory (use --config flag)")
	}

	input, _, err := LoadConfig(configFlag, adapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	input = caddy.RemoveMetaFields(input)

	var cfg *caddy.Config
	err = caddy.StrictUnmarshalJSON(input, &cfg)
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

func cmdFmt(fl Flags) (int, error) {
	configFile := fl.Arg(0)
	configFlag := fl.String("config")
	if (len(fl.Args()) > 1) || (configFlag != "" && configFile != "") {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("fmt does not support multiple files %s %s", configFlag, strings.Join(fl.Args(), " "))
	}
	if configFile == "" && configFlag == "" {
		configFile = "Caddyfile"
	} else if configFile == "" {
		configFile = configFlag
	}
	// as a special case, read from stdin if the file name is "-"
	if configFile == "-" {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("reading stdin: %v", err)
		}
		fmt.Print(string(caddyfile.Format(input)))
		return caddy.ExitCodeSuccess, nil
	}

	input, err := os.ReadFile(configFile)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	output := caddyfile.Format(input)

	if fl.Bool("overwrite") {
		if err := os.WriteFile(configFile, output, 0o600); err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("overwriting formatted file: %v", err)
		}
		return caddy.ExitCodeSuccess, nil
	}

	if fl.Bool("diff") {
		diff := difflib.Diff(
			strings.Split(string(input), "\n"),
			strings.Split(string(output), "\n"))
		for _, d := range diff {
			switch d.Delta {
			case difflib.Common:
				fmt.Printf("  %s\n", d.Payload)
			case difflib.LeftOnly:
				fmt.Printf("- %s\n", d.Payload)
			case difflib.RightOnly:
				fmt.Printf("+ %s\n", d.Payload)
			}
		}
	} else {
		fmt.Print(string(output))
	}

	if warning, diff := caddyfile.FormattingDifference(configFile, input); diff {
		return caddy.ExitCodeFailedStartup, fmt.Errorf(`%s:%d: Caddyfile input is not formatted; Tip: use '--overwrite' to update your Caddyfile in-place instead of previewing it. Consult '--help' for more options`,
			warning.File,
			warning.Line,
		)
	}

	return caddy.ExitCodeSuccess, nil
}

// handleEnvFileFlag loads the environment variables from the given --envfile
// flag if specified. This should be called as early in the command function.
func handleEnvFileFlag(fl Flags) error {
	var err error
	var envfileFlag []string
	envfileFlag, err = fl.GetStringSlice("envfile")
	if err != nil {
		return fmt.Errorf("reading envfile flag: %v", err)
	}

	for _, envfile := range envfileFlag {
		if err := loadEnvFromFile(envfile); err != nil {
			return fmt.Errorf("loading additional environment variables: %v", err)
		}
	}

	return nil
}

// AdminAPIRequest makes an API request according to the CLI flags given,
// with the given HTTP method and request URI. If body is non-nil, it will
// be assumed to be Content-Type application/json. The caller should close
// the response body. Should only be used by Caddy CLI commands which
// need to interact with a running instance of Caddy via the admin API.
func AdminAPIRequest(adminAddr, method, uri string, headers http.Header, body io.Reader) (*http.Response, error) {
	parsedAddr, err := caddy.ParseNetworkAddress(adminAddr)
	if err != nil || parsedAddr.PortRangeSize() > 1 {
		return nil, fmt.Errorf("invalid admin address %s: %v", adminAddr, err)
	}
	origin := "http://" + parsedAddr.JoinHostPort(0)
	if parsedAddr.IsUnixNetwork() {
		origin = "http://127.0.0.1" // bogus host is a hack so that http.NewRequest() is happy

		// the unix address at this point might still contain the optional
		// unix socket permissions, which are part of the address/host.
		// those need to be removed first, as they aren't part of the
		// resulting unix file path
		addr, _, err := internal.SplitUnixSocketPermissionsBits(parsedAddr.Host)
		if err != nil {
			return nil, err
		}
		parsedAddr.Host = addr
	} else if parsedAddr.IsFdNetwork() {
		origin = "http://127.0.0.1"
	}

	// form the request
	req, err := http.NewRequest(method, origin+uri, body)
	if err != nil {
		return nil, fmt.Errorf("making request: %v", err)
	}
	if parsedAddr.IsUnixNetwork() || parsedAddr.IsFdNetwork() {
		// We used to conform to RFC 2616 Section 14.26 which requires
		// an empty host header when there is no host, as is the case
		// with unix sockets and socket fds. However, Go required a
		// Host value so we used a hack of a space character as the host
		// (it would see the Host was non-empty, then trim the space later).
		// As of Go 1.20.6 (July 2023), this hack no longer works. See:
		// https://github.com/golang/go/issues/60374
		// See also the discussion here:
		// https://github.com/golang/go/issues/61431
		//
		// After that, we now require a Host value of either 127.0.0.1
		// or ::1 if one is set. Above I choose to use 127.0.0.1. Even
		// though the value should be completely irrelevant (it could be
		// "srldkjfsd"), if for some reason the Host *is* used, at least
		// we can have some reasonable assurance it will stay on the local
		// machine and that browsers, if they ever allow access to unix
		// sockets, can still enforce CORS, ensuring it is still coming
		// from the local machine.
	} else {
		req.Header.Set("Origin", origin)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header[k] = v
	}

	// make an HTTP client that dials our network type, since admin
	// endpoints aren't always TCP, which is what the default transport
	// expects; reuse is not of particular concern here
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(parsedAddr.Network, parsedAddr.JoinHostPort(0))
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %v", err)
	}

	// if it didn't work, let the user know
	if resp.StatusCode >= 400 {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024*2))
		if err != nil {
			return nil, fmt.Errorf("HTTP %d: reading error message: %v", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("caddy responded with error: HTTP %d: %s", resp.StatusCode, respBody)
	}

	return resp, nil
}

// DetermineAdminAPIAddress determines which admin API endpoint address should
// be used based on the inputs. By priority: if `address` is specified, then
// it is returned; if `config` is specified, then that config will be used for
// finding the admin address; if `configFile` (and `configAdapter`) are specified,
// then that config will be loaded to find the admin address; otherwise, the
// default admin listen address will be returned.
func DetermineAdminAPIAddress(address string, config []byte, configFile, configAdapter string) (string, error) {
	// Prefer the address if specified and non-empty
	if address != "" {
		return address, nil
	}

	// Try to load the config from file if specified, with the given adapter name
	if configFile != "" {
		var loadedConfigFile string
		var err error

		// use the provided loaded config if non-empty
		// otherwise, load it from the specified file/adapter
		loadedConfig := config
		if len(loadedConfig) == 0 {
			// get the config in caddy's native format
			loadedConfig, loadedConfigFile, err = LoadConfig(configFile, configAdapter)
			if err != nil {
				return "", err
			}
			if loadedConfigFile == "" {
				return "", fmt.Errorf("no config file to load; either use --config flag or ensure Caddyfile exists in current directory")
			}
		}

		// get the address of the admin listener from the config
		if len(loadedConfig) > 0 {
			var tmpStruct struct {
				Admin caddy.AdminConfig `json:"admin"`
			}
			err := json.Unmarshal(loadedConfig, &tmpStruct)
			if err != nil {
				return "", fmt.Errorf("unmarshaling admin listener address from config: %v", err)
			}
			if tmpStruct.Admin.Listen != "" {
				return tmpStruct.Admin.Listen, nil
			}
		}
	}

	// Fallback to the default listen address otherwise
	return caddy.DefaultAdminListen, nil
}

// configFileWithRespectToDefault returns the filename to use for loading the config, based
// on whether a config file is already specified and a supported default config file exists.
func configFileWithRespectToDefault(logger *zap.Logger, configFile string) (string, error) {
	const defaultCaddyfile = "Caddyfile"

	// if no input file was specified, try a default Caddyfile if the Caddyfile adapter is plugged in
	if configFile == "" && caddyconfig.GetAdapter("caddyfile") != nil {
		_, err := os.Stat(defaultCaddyfile)
		if err == nil {
			// default Caddyfile exists
			if logger != nil {
				logger.Info("using adjacent Caddyfile")
			}
			return defaultCaddyfile, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			// problem checking
			return configFile, fmt.Errorf("checking if default Caddyfile exists: %v", err)
		}
	}

	// default config file does not exist or is irrelevant
	return configFile, nil
}

type moduleInfo struct {
	caddyModuleID string
	goModule      *debug.Module
	err           error
}
