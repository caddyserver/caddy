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
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"text/template"

	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/keybase/go-ps"
	"github.com/mholt/certmagic"
)

type cmdStart struct {
	config        string
	configAdapter string
}

func newCmdStart() *command {
	start := cmdStart{}
	cmd := &command{
		Run: start.run,
		Usage: "caddy start [--config <path>] [--config-adapter <name>]",
		Short: "Starts the Caddy process, blocks until server initiated",
		Long: `Starts the Caddy process, optionally bootstrapped with an initial
config file. Blocks until server is successfully running (or fails to run),
then returns. On Windows, the child process will remain attached to the
terminal, so closing the window will forcefully stop Caddy. See run for more
details.`,
	}

	fs := flag.NewFlagSet("start", flag.ExitOnError)
	fs.StringVar(&start.config, "config", "", "Configuration file")
	fs.StringVar(&start.configAdapter, "config-adapter", "", "Name of config adapter to apply")
	cmd.Flag = fs
	return cmd
}

func (c *cmdStart) run([]string) (int, error) {
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
	if c.config != "" {
		cmd.Args = append(cmd.Args, "--config", c.config)
	}
	if c.configAdapter != "" {
		cmd.Args = append(cmd.Args, "--config-adapter", c.configAdapter)
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

type cmdRun struct {
	config        string
	configAdapter string
	printEnv      bool
	pingback      string
}

func newCmdRun() *command {
	run := cmdRun{}
	cmd := &command{
		Run:   run.run,
		Usage: "caddy run [--config <path>] [--config-adapter <name>] [--print-env]",
		Short: `Starts the Caddy process, blocks indefinitely`,
		Long: `Same as start, but blocks indefinitely; i.e. runs Caddy in "daemon" mode. On
Windows, this is recommended over caddy start when running Caddy manually since
it will be more obvious that Caddy is still running and bound to the terminal
window.

If a config file is specified, it will be applied immediately after the process
is running. If the config file is not in Caddy's native JSON format, you can
specify an adapter with --config-adapter to adapt the given config file to
Caddy's native format. The config adapter must be a registered module. Any
warnings will be printed to the log, but beware that any adaptation without
errors will immediately be used. If you want to review the results of the
adaptation first, use adapt-config.

As a special case, if the current working directory has a file called
"Caddyfile" and the caddyfile config adapter is plugged in (default), then that
file will be loaded and used to configure Caddy, even without any command line
flags.

If --print-env is specified, the environment as seen by the Caddy process will
be printed before starting. This is the same as the environ command but does
not quit after printing.`,
	}

	fs := flag.NewFlagSet("start", flag.ExitOnError)
	fs.StringVar(&run.config, "config", "", "Configuration file")
	fs.StringVar(&run.configAdapter, "config-adapter", "", "Name of config adapter to apply")
	fs.BoolVar(&run.printEnv, "print-env", false, "Print environment")
	fs.StringVar(&run.pingback, "pingback", "", "Echo confirmation bytes to this address on success")

	cmd.Flag = fs
	return cmd
}

func (c *cmdRun) run(args []string) (int, error) {
	// if we are supposed to print the environment, do that first
	if c.printEnv {
		cmd := newCmdEnviron()
		exitCode, err := cmd.Run(nil)
		if err != nil {
			return exitCode, err
		}
	}

	// get the config in caddy's native format
	config, err := loadConfig(c.config, c.configAdapter)
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
	if c.pingback != "" {
		confirmationBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("reading confirmation bytes from stdin: %v", err)
		}
		conn, err := net.Dial("tcp", c.pingback)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("dialing confirmation address: %v", err)
		}
		defer conn.Close()
		_, err = conn.Write(confirmationBytes)
		if err != nil {
			return caddy.ExitCodeFailedStartup,
				fmt.Errorf("writing confirmation bytes to %s: %v", c.pingback, err)
		}
	}

	select {}
}

type cmdStop struct{}

func newCmdStop() *command {
	stop := cmdStop{}
	cmd := &command{
		Run:   stop.run,
		Usage: "caddy stop",
		Short: "Gracefully stops the running Caddy process",
		Long: `Gracefully stops the running Caddy process. (Note: this will stop any process
named the same as the executable.) On Windows, this stop is forceful and Caddy
will not have an opportunity to clean up any active locks; for a graceful
shutdown on Windows, use Ctrl+C or the /stop endpoint.`,
	}

	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	cmd.Flag = fs
	return cmd
}

func (c *cmdStop) run(args []string) (int, error) {
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

type cmdReload struct {
	config        string
	configAdapter string
	address       string
}

func newCmdReload() *command {
	reload := cmdReload{}
	cmd := &command{
		Run:   reload.run,
		Usage: "caddy reload --config <path> [--config-adapter <name>] [--address <interface>]",
		Short: "Gives the running Caddy instance a new configuration",
		Long: `Gives the running Caddy instance a new configuration. This has the same effect
as POSTing a document to the /load endpoint, but is convenient for simple
workflows revolving around config files. Since the admin endpoint is
configurable, the endpoint configuration is loaded from the --address flag if
specified; otherwise it is loaded from the given config file; otherwise the
default is assumed.`,
	}

	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	fs.StringVar(&reload.config, "config", "", "Configuration file")
	fs.StringVar(&reload.configAdapter, "config-adapter", "", "Name of config adapter to apply")
	fs.StringVar(&reload.address, "address", "", "Address of the administration listener, if different from config")
	cmd.Flag = fs

	return cmd
}

func (c *cmdReload) run(args []string) (int, error) {
	// a configuration is required
	if c.config == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("no configuration to load (use --config)")
	}

	// get the config in caddy's native format
	config, err := loadConfig(c.config, c.configAdapter)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// get the address of the admin listener and craft endpoint URL
	adminAddr := c.address
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

type cmdVersion struct{}

func newCmdVersion() *command {
	version := cmdVersion{}
	cmd := &command{
		Run:   version.run,
		Usage: "caddy version",
		Short: "Prints the version",
		Long:  `Prints the version.`,
	}

	fs := flag.NewFlagSet("version", flag.ExitOnError)
	cmd.Flag = fs
	return cmd
}

func (c *cmdVersion) run(args []string) (int, error) {
	goModule := caddy.GoModule()
	if goModule.Sum != "" {
		// a build with a known version will also have a checksum
		fmt.Printf("%s %s\n", goModule.Version, goModule.Sum)
	} else {
		fmt.Println(goModule.Version)
	}
	return caddy.ExitCodeSuccess, nil
}

type cmdListModules struct {
}

func newCmdListModules() *command {
	listModules := cmdListModules{}
	cmd := &command{
		Run:   listModules.run,
		Usage: "caddy list-modules",
		Short: "Prints the modules installed",
		Long:  `Prints the modules installed.`,
	}

	fs := flag.NewFlagSet("listModules", flag.ExitOnError)
	cmd.Flag = fs
	return cmd
}

func (c *cmdListModules) run(args []string) (int, error) {
	for _, m := range caddy.Modules() {
		fmt.Println(m)
	}
	return caddy.ExitCodeSuccess, nil
}

type cmdEnviron struct {
}

func newCmdEnviron() *command {
	environ := &cmdEnviron{}
	cmd := &command{
		Run:   environ.run,
		Usage: "caddy environ",
		Short: "Prints the environment as seen by caddy",
		Long: `Prints the environment as seen by caddy. Can be useful when debugging init
systems or process manager units like systemd.`,
	}

	fs := flag.NewFlagSet("environ", flag.ExitOnError)
	cmd.Flag = fs
	return cmd
}

func (c *cmdEnviron) run(args []string) (int, error) {
	for _, v := range os.Environ() {
		fmt.Println(v)
	}
	return caddy.ExitCodeSuccess, nil
}

type cmdAdaptConfig struct {
	adapter string
	input   string
	pretty  bool
}

func newCmdAdaptConfig() *command {
	adaptConfig := &cmdAdaptConfig{}
	cmd := &command{
		Run:   adaptConfig.run,
		Usage: "caddy adapt-config --input <path> --adapter <name> [--pretty]",
		Short: "Adapts a configuration to Caddy's native JSON config structure",
		Long: `Adapts a configuration to Caddy's native JSON config structure and writes the
output to stdout, along with any warnings to stderr. If --pretty is specified,
the output will be formatted with indentation for human readability.`,
	}

	fs := flag.NewFlagSet("adaptConfig", flag.ExitOnError)
	fs.StringVar(&adaptConfig.adapter, "adapter", "", "Name of config adapter")
	fs.StringVar(&adaptConfig.input, "input", "", "Configuration file to adapt")
	fs.BoolVar(&adaptConfig.pretty, "pretty", false, "Format the output for human readability")
	cmd.Flag = fs
	return cmd
}

func (c *cmdAdaptConfig) run(args []string) (int, error) {
	if c.adapter == "" || c.input == "" {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("usage: caddy adapt-config --adapter <name> --input <file>")
	}

	cfgAdapter := caddyconfig.GetAdapter(c.adapter)
	if cfgAdapter == nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("unrecognized config adapter: %s", c.adapter)
	}

	input, err := ioutil.ReadFile(c.input)
	if err != nil {
		return caddy.ExitCodeFailedStartup,
			fmt.Errorf("reading input file: %v", err)
	}

	opts := make(map[string]interface{})
	if c.pretty {
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
		log.Printf("[WARNING][%s] %s:%d: %s", c.adapter, warn.File, warn.Line, msg)
	}

	// print result to stdout
	fmt.Println(string(adaptedConfig))

	return caddy.ExitCodeSuccess, nil
}

type cmdHelp struct{}

func newCmdHelp() *command {
	help := cmdHelp{}
	cmd := &command{
		Run:   help.run,
		Usage: "caddy help [command]",
		Short: "Help for each command",
		Long:  `Prints help for each command.`,
	}

	fs := flag.NewFlagSet("help", flag.ExitOnError)
	cmd.Flag = fs
	return cmd
}

var helpTemplate = `{{ .Long }}

Full documentation available on 
https://github.com/caddyserver/caddy/wiki/v2:-Documentation

usage:
  {{ .Usage }}
{{ if ne .FlagHelp "" }}
flags:
{{ .FlagHelp }}{{ end }}`

func (c *cmdHelp) run(args []string) (int, error) {
	if len(args) == 0 {
		msg, err := usageString()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(caddy.ExitCodeFailedStartup)
		}
		fmt.Print(msg)
		return caddy.ExitCodeSuccess, nil
	} else if len(args) > 1 {
		return caddy.ExitCodeFailedStartup, errors.New(
			"usage: caddy help [command]\n" + "Too many arguments given.\n")
	}

	subcommand, ok := commandMap[args[0]]
	if !ok {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unknown command '%s'. Run 'caddy help' for usage.", args[0])
	}

	cmdhelp := template.Must(template.New("cmdhelp").Parse(helpTemplate))
	if err := cmdhelp.Execute(os.Stdout, subcommand); err != nil {
		log.Println(err)
		return caddy.ExitCodeFailedStartup, err
	}
	return caddy.ExitCodeSuccess, nil
}
