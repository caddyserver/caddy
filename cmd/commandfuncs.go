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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func cmdStart(fl Flags) (int, error) {
	startCmdConfigFlag := fl.String("config")
	startCmdConfigAdapterFlag := fl.String("adapter")
	startCmdPidfileFlag := fl.String("pidfile")
	startCmdWatchFlag := fl.Bool("watch")
	startCmdEnvfileFlag := fl.String("envfile")

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
	if startCmdEnvfileFlag != "" {
		cmd.Args = append(cmd.Args, "--envfile", startCmdEnvfileFlag)
	}
	if startCmdConfigAdapterFlag != "" {
		cmd.Args = append(cmd.Args, "--adapter", startCmdConfigAdapterFlag)
	}
	if startCmdWatchFlag {
		cmd.Args = append(cmd.Args, "--watch")
	}
	if startCmdPidfileFlag != "" {
		cmd.Args = append(cmd.Args, "--pidfile", startCmdPidfileFlag)
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
	// started yet, and writing synchronously would result
	// in a deadlock
	go func() {
		_, _ = stdinpipe.Write(expect)
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
		fmt.Printf("Successfully started Caddy (pid=%d) - Caddy is running in the background\n", cmd.Process.Pid)
	case err := <-exit:
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("caddy process exited with error: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdRun(fl Flags) (int, error) {
	caddy.TrapSignals()

	runCmdConfigFlag := fl.String("config")
	runCmdConfigAdapterFlag := fl.String("adapter")
	runCmdResumeFlag := fl.Bool("resume")
	runCmdLoadEnvfileFlag := fl.String("envfile")
	runCmdPrintEnvFlag := fl.Bool("environ")
	runCmdWatchFlag := fl.Bool("watch")
	runCmdPidfileFlag := fl.String("pidfile")
	runCmdPingbackFlag := fl.String("pingback")

	// load all additional envs as soon as possible
	if runCmdLoadEnvfileFlag != "" {
		if err := loadEnvFromFile(runCmdLoadEnvfileFlag); err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("loading additional environment variables: %v", err)
		}
	}

	// if we are supposed to print the environment, do that first
	if runCmdPrintEnvFlag {
		printEnvironment()
	}

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
			if runCmdConfigFlag == "" {
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
	if !runCmdResumeFlag {
		config, configFile, err = loadConfig(runCmdConfigFlag, runCmdConfigAdapterFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
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

	// if enabled, reload config file automatically on changes
	// (this better only be used in dev!)
	if runCmdWatchFlag {
		go watchConfigFile(configFile, runCmdConfigAdapterFlag)
	}

	// create pidfile
	if runCmdPidfileFlag != "" {
		err := caddy.PIDFile(runCmdPidfileFlag)
		if err != nil {
			caddy.Log().Error("unable to write PID file",
				zap.String("pidfile", runCmdPidfileFlag),
				zap.Error(err))
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

	err := apiRequest(stopCmdAddrFlag, http.MethodPost, "/stop", nil, nil)
	if err != nil {
		caddy.Log().Warn("failed using API to stop instance", zap.Error(err))
		return caddy.ExitCodeFailedStartup, err
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdReload(fl Flags) (int, error) {
	reloadCmdConfigFlag := fl.String("config")
	reloadCmdConfigAdapterFlag := fl.String("adapter")
	reloadCmdAddrFlag := fl.String("address")
	reloadCmdForceFlag := fl.Bool("force")

	// get the config in caddy's native format
	config, configFile, err := loadConfig(reloadCmdConfigFlag, reloadCmdConfigAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	if configFile == "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("no config file to load")
	}

	// get the address of the admin listener; use flag if specified
	adminAddr := reloadCmdAddrFlag
	if adminAddr == "" && len(config) > 0 {
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

	// optionally force a config reload
	headers := make(http.Header)
	if reloadCmdForceFlag {
		headers.Set("Cache-Control", "must-revalidate")
	}

	err = apiRequest(adminAddr, http.MethodPost, "/load", headers, bytes.NewReader(config))
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("sending configuration to instance: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdVersion(_ Flags) (int, error) {
	fmt.Println(caddyVersion())
	return caddy.ExitCodeSuccess, nil
}

func cmdBuildInfo(fl Flags) (int, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("no build information")
	}

	fmt.Printf("go_version: %s\n", runtime.Version())
	fmt.Printf("go_os:      %s\n", runtime.GOOS)
	fmt.Printf("go_arch:    %s\n", runtime.GOARCH)
	fmt.Printf("path:       %s\n", bi.Path)
	fmt.Printf("main:       %s %s %s\n", bi.Main.Path, bi.Main.Version, bi.Main.Sum)
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
	packages := fl.Bool("packages")
	versions := fl.Bool("versions")

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

	if len(standard) > 0 {
		for _, mod := range standard {
			printModuleInfo(mod)
		}
	}
	fmt.Printf("\n  Standard modules: %d\n", len(standard))
	if len(nonstandard) > 0 {
		if len(standard) > 0 {
			fmt.Println()
		}
		for _, mod := range nonstandard {
			printModuleInfo(mod)
		}
	}
	fmt.Printf("\n  Non-standard modules: %d\n", len(nonstandard))
	if len(unknown) > 0 {
		if len(standard) > 0 || len(nonstandard) > 0 {
			fmt.Println()
		}
		for _, mod := range unknown {
			printModuleInfo(mod)
		}
	}
	fmt.Printf("\n  Unknown modules: %d\n", len(unknown))

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

	// if no input file was specified, try a default
	// Caddyfile if the Caddyfile adapter is plugged in
	if adaptCmdInputFlag == "" && caddyconfig.GetAdapter("caddyfile") != nil {
		_, err := os.Stat("Caddyfile")
		if err == nil {
			// default Caddyfile exists
			adaptCmdInputFlag = "Caddyfile"
			caddy.Log().Info("using adjacent Caddyfile")
		} else if !os.IsNotExist(err) {
			// default Caddyfile exists, but error accessing it
			return caddy.ExitCodeFailedStartup, fmt.Errorf("accessing default Caddyfile: %v", err)
		}
	}

	if adaptCmdInputFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("input file required when there is no Caddyfile in current directory (use --config flag)")
	}
	if adaptCmdAdapterFlag == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("adapter name is required (use --adapt flag or leave unspecified for default)")
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

	opts := map[string]interface{}{"filename": adaptCmdInputFlag}

	adaptedConfig, warnings, err := cfgAdapter.Adapt(input, opts)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if adaptCmdPrettyFlag {
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
		fmt.Fprintf(os.Stderr, "[WARNING][%s] %s:%d: %s\n", adaptCmdAdapterFlag, warn.File, warn.Line, msg)
	}

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

	input, _, err := loadConfig(validateCmdConfigFlag, validateCmdAdapterFlag)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
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

func cmdFmt(fl Flags) (int, error) {
	formatCmdConfigFile := fl.Arg(0)
	if formatCmdConfigFile == "" {
		formatCmdConfigFile = "Caddyfile"
	}

	// as a special case, read from stdin if the file name is "-"
	if formatCmdConfigFile == "-" {
		input, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("reading stdin: %v", err)
		}
		fmt.Print(string(caddyfile.Format(input)))
		return caddy.ExitCodeSuccess, nil
	}

	input, err := ioutil.ReadFile(formatCmdConfigFile)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	output := caddyfile.Format(input)

	if fl.Bool("overwrite") {
		if err := ioutil.WriteFile(formatCmdConfigFile, output, 0600); err != nil {
			return caddy.ExitCodeFailedStartup, nil
		}
	} else {
		fmt.Print(string(output))
	}

	return caddy.ExitCodeSuccess, nil
}

func cmdUpgrade(_ Flags) (int, error) {
	l := caddy.Log()

	thisExecPath, err := os.Executable()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("determining current executable path: %v", err)
	}
	thisExecStat, err := os.Stat(thisExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("retrieving current executable permission bits: %v", err)
	}
	l.Info("this executable will be replaced", zap.String("path", thisExecPath))

	// get the list of nonstandard plugins
	_, nonstandard, _, err := getModules()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unable to enumerate installed plugins: %v", err)
	}
	pluginPkgs := make(map[string]struct{})
	for _, mod := range nonstandard {
		if mod.goModule.Replace != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("cannot auto-upgrade when Go module has been replaced: %s => %s",
				mod.goModule.Path, mod.goModule.Replace.Path)
		}
		l.Info("found non-standard module",
			zap.String("id", mod.caddyModuleID),
			zap.String("package", mod.goModule.Path))
		pluginPkgs[mod.goModule.Path] = struct{}{}
	}

	// build the request URL to download this custom build
	qs := url.Values{
		"os":   {runtime.GOOS},
		"arch": {runtime.GOARCH},
	}
	for pkg := range pluginPkgs {
		qs.Add("p", pkg)
	}
	urlStr := fmt.Sprintf("https://caddyserver.com/api/download?%s", qs.Encode())

	// initiate the build
	l.Info("requesting build",
		zap.String("os", qs.Get("os")),
		zap.String("arch", qs.Get("arch")),
		zap.Strings("packages", qs["p"]))
	resp, err := http.Get(urlStr)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("secure request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var details struct {
			StatusCode int `json:"status_code"`
			Error      struct {
				Message string `json:"message"`
				ID      string `json:"id"`
			} `json:"error"`
		}
		err2 := json.NewDecoder(resp.Body).Decode(&details)
		if err2 != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("download and error decoding failed: HTTP %d: %v", resp.StatusCode, err2)
		}
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download failed: HTTP %d: %s (id=%s)", resp.StatusCode, details.Error.Message, details.Error.ID)
	}

	// back up the current binary, in case something goes wrong we can replace it
	backupExecPath := thisExecPath + ".tmp"
	l.Info("build acquired; backing up current executable",
		zap.String("current_path", thisExecPath),
		zap.String("backup_path", backupExecPath))
	err = os.Rename(thisExecPath, backupExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("backing up current binary: %v", err)
	}
	defer func() {
		if err != nil {
			err2 := os.Rename(backupExecPath, thisExecPath)
			if err2 != nil {
				l.Error("restoring original executable failed; will need to be restored manually",
					zap.String("backup_path", backupExecPath),
					zap.String("original_path", thisExecPath),
					zap.Error(err2))
			}
		}
	}()

	// download the file; do this in a closure to close reliably before we execute it
	writeFile := func() error {
		destFile, err := os.OpenFile(thisExecPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, thisExecStat.Mode())
		if err != nil {
			return fmt.Errorf("unable to open destination file: %v", err)
		}
		defer destFile.Close()

		l.Info("downloading binary", zap.String("source", urlStr), zap.String("destination", thisExecPath))

		_, err = io.Copy(destFile, resp.Body)
		if err != nil {
			return fmt.Errorf("unable to download file: %v", err)
		}

		err = destFile.Sync()
		if err != nil {
			return fmt.Errorf("syncing downloaded file to device: %v", err)
		}

		return nil
	}
	err = writeFile()
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	l.Info("download successful; displaying new binary details", zap.String("location", thisExecPath))

	// use the new binary to print out version and module info
	fmt.Print("\nModule versions:\n\n")
	cmd := exec.Command(thisExecPath, "list-modules", "--versions")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to execute: %v", err)
	}
	fmt.Println("\nVersion:")
	cmd = exec.Command(thisExecPath, "version")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to execute: %v", err)
	}
	fmt.Println()

	// clean up the backup file
	err = os.Remove(backupExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to clean up backup binary: %v", err)
	}

	l.Info("upgrade successful; please restart any running Caddy instances", zap.String("executable", thisExecPath))

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

func getModules() (standard, nonstandard, unknown []moduleInfo, err error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		err = fmt.Errorf("no build info")
		return
	}

	for _, modID := range caddy.Modules() {
		modInfo, err := caddy.GetModule(modID)
		if err != nil {
			// that's weird, shouldn't happen
			unknown = append(unknown, moduleInfo{caddyModuleID: modID, err: err})
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

		caddyModGoMod := moduleInfo{caddyModuleID: modID, goModule: matched}

		if strings.HasPrefix(modPkgPath, caddy.ImportPath) {
			standard = append(standard, caddyModGoMod)
		} else {
			nonstandard = append(nonstandard, caddyModGoMod)
		}
	}
	return
}

// apiRequest makes an API request to the endpoint adminAddr with the
// given HTTP method and request URI. If body is non-nil, it will be
// assumed to be Content-Type application/json.
func apiRequest(adminAddr, method, uri string, headers http.Header, body io.Reader) error {
	// parse the admin address
	if adminAddr == "" {
		adminAddr = caddy.DefaultAdminListen
	}
	parsedAddr, err := caddy.ParseNetworkAddress(adminAddr)
	if err != nil || parsedAddr.PortRangeSize() > 1 {
		return fmt.Errorf("invalid admin address %s: %v", adminAddr, err)
	}
	origin := parsedAddr.JoinHostPort(0)
	if parsedAddr.IsUnixNetwork() {
		origin = "unixsocket" // hack so that http.NewRequest() is happy
	}

	// form the request
	req, err := http.NewRequest(method, "http://"+origin+uri, body)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}
	if parsedAddr.IsUnixNetwork() {
		// When listening on a unix socket, the admin endpoint doesn't
		// accept any Host header because there is no host:port for
		// a unix socket's address. The server's host check is fairly
		// strict for security reasons, so we don't allow just any
		// Host header. For unix sockets, the Host header must be
		// empty. Unfortunately, Go makes it impossible to make HTTP
		// requests with an empty Host header... except with this one
		// weird trick. (Hopefully they don't fix it. It's already
		// hard enough to use HTTP over unix sockets.)
		//
		// An equivalent curl command would be something like:
		// $ curl --unix-socket caddy.sock http:/:$REQUEST_URI
		req.URL.Host = " "
		req.Host = ""
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

type moduleInfo struct {
	caddyModuleID string
	goModule      *debug.Module
	err           error
}
