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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/caddyserver/certmagic"
	"github.com/spf13/pflag"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func init() {
	// set a fitting User-Agent for ACME requests
	version, _ := caddy.Version()
	cleanModVersion := strings.TrimPrefix(version, "v")
	ua := "Caddy/" + cleanModVersion
	if uaEnv, ok := os.LookupEnv("USERAGENT"); ok {
		ua = uaEnv + " " + ua
	}
	certmagic.UserAgent = ua

	// by using Caddy, user indicates agreement to CA terms
	// (very important, as Caddy is often non-interactive
	// and thus ACME account creation will fail!)
	certmagic.DefaultACME.Agreed = true
}

// Main implements the main function of the caddy command.
// Call this if Caddy is to be the main() of your program.
func Main() {
	if len(os.Args) == 0 {
		fmt.Printf("[FATAL] no arguments provided by OS; args[0] must be command\n")
		os.Exit(caddy.ExitCodeFailedStartup)
	}

	logger := caddy.Log()

	// Configure the maximum number of CPUs to use to match the Linux container quota (if any)
	// See https://pkg.go.dev/runtime#GOMAXPROCS
	undo, err := maxprocs.Set(maxprocs.Logger(logger.Sugar().Infof))
	defer undo()
	if err != nil {
		caddy.Log().Warn("failed to set GOMAXPROCS", zap.Error(err))
	}

	// Configure the maximum memory to use to match the Linux container quota (if any) or system memory
	// See https://pkg.go.dev/runtime/debug#SetMemoryLimit
	_, _ = memlimit.SetGoMemLimitWithOpts(
		memlimit.WithLogger(
			slog.New(zapslog.NewHandler(logger.Core())),
		),
		memlimit.WithProvider(
			memlimit.ApplyFallback(
				memlimit.FromCgroup,
				memlimit.FromSystem,
			),
		),
	)

	if err := defaultFactory.Build().Execute(); err != nil {
		var exitError *exitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode)
		}
		os.Exit(1)
	}
}

// handlePingbackConn reads from conn and ensures it matches
// the bytes in expect, or returns an error if it doesn't.
func handlePingbackConn(conn net.Conn, expect []byte) error {
	defer conn.Close()
	confirmationBytes, err := io.ReadAll(io.LimitReader(conn, 32))
	if err != nil {
		return err
	}
	if !bytes.Equal(confirmationBytes, expect) {
		return fmt.Errorf("wrong confirmation: %x", confirmationBytes)
	}
	return nil
}

// LoadConfig loads the config from configFile and adapts it
// using adapterName. If adapterName is specified, configFile
// must be also. If no configFile is specified, it tries
// loading a default config file. The lack of a config file is
// not treated as an error, but false will be returned if
// there is no config available. It prints any warnings to stderr,
// and returns the resulting JSON config bytes along with
// the name of the loaded config file (if any).
func LoadConfig(configFile, adapterName string) ([]byte, string, error) {
	return loadConfigWithLogger(caddy.Log(), configFile, adapterName)
}

func isCaddyfile(configFile, adapterName string) (bool, error) {
	if adapterName == "caddyfile" {
		return true, nil
	}

	// as a special case, if a config file starts with "caddyfile" or
	// has a ".caddyfile" extension, and no adapter is specified, and
	// no adapter module name matches the extension, assume
	// caddyfile adapter for convenience
	baseConfig := strings.ToLower(filepath.Base(configFile))
	baseConfigExt := filepath.Ext(baseConfig)
	startsOrEndsInCaddyfile := strings.HasPrefix(baseConfig, "caddyfile") || strings.HasSuffix(baseConfig, ".caddyfile")

	if baseConfigExt == ".json" {
		return false, nil
	}

	// If the adapter is not specified,
	// the config file starts with "caddyfile",
	// the config file has an extension,
	// and isn't a JSON file (e.g. Caddyfile.yaml),
	// then we don't know what the config format is.
	if adapterName == "" && startsOrEndsInCaddyfile {
		return true, nil
	}

	// adapter is not empty,
	// adapter is not "caddyfile",
	// extension is not ".json",
	// extension is not ".caddyfile"
	// file does not start with "Caddyfile"
	return false, nil
}

func loadConfigWithLogger(logger *zap.Logger, configFile, adapterName string) ([]byte, string, error) {
	// if no logger is provided, use a nop logger
	// just so we don't have to check for nil
	if logger == nil {
		logger = zap.NewNop()
	}

	// specifying an adapter without a config file is ambiguous
	if adapterName != "" && configFile == "" {
		return nil, "", fmt.Errorf("cannot adapt config without config file (use --config)")
	}

	// load initial config and adapter
	var config []byte
	var cfgAdapter caddyconfig.Adapter
	var err error
	if configFile != "" {
		if configFile == "-" {
			config, err = io.ReadAll(os.Stdin)
			if err != nil {
				return nil, "", fmt.Errorf("reading config from stdin: %v", err)
			}
			logger.Info("using config from stdin")
		} else {
			config, err = os.ReadFile(configFile)
			if err != nil {
				return nil, "", fmt.Errorf("reading config from file: %v", err)
			}
			logger.Info("using config from file", zap.String("file", configFile))
		}
	} else if adapterName == "" {
		// if the Caddyfile adapter is plugged in, we can try using an
		// adjacent Caddyfile by default
		cfgAdapter = caddyconfig.GetAdapter("caddyfile")
		if cfgAdapter != nil {
			config, err = os.ReadFile("Caddyfile")
			if errors.Is(err, fs.ErrNotExist) {
				// okay, no default Caddyfile; pretend like this never happened
				cfgAdapter = nil
			} else if err != nil {
				// default Caddyfile exists, but error reading it
				return nil, "", fmt.Errorf("reading default Caddyfile: %v", err)
			} else {
				// success reading default Caddyfile
				configFile = "Caddyfile"
				logger.Info("using adjacent Caddyfile")
			}
		}
	}

	if yes, err := isCaddyfile(configFile, adapterName); yes {
		adapterName = "caddyfile"
	} else if err != nil {
		return nil, "", err
	}

	// load config adapter
	if adapterName != "" {
		cfgAdapter = caddyconfig.GetAdapter(adapterName)
		if cfgAdapter == nil {
			return nil, "", fmt.Errorf("unrecognized config adapter: %s", adapterName)
		}
	}

	// adapt config
	if cfgAdapter != nil {
		adaptedConfig, warnings, err := cfgAdapter.Adapt(config, map[string]any{
			"filename": configFile,
		})
		if err != nil {
			return nil, "", fmt.Errorf("adapting config using %s: %v", adapterName, err)
		}
		logger.Info("adapted config to JSON", zap.String("adapter", adapterName))
		for _, warn := range warnings {
			msg := warn.Message
			if warn.Directive != "" {
				msg = fmt.Sprintf("%s: %s", warn.Directive, warn.Message)
			}
			logger.Warn(msg,
				zap.String("adapter", adapterName),
				zap.String("file", warn.File),
				zap.Int("line", warn.Line))
		}
		config = adaptedConfig
	} else if len(config) != 0 {
		// validate that the config is at least valid JSON
		err = json.Unmarshal(config, new(any))
		if err != nil {
			return nil, "", fmt.Errorf("config is not valid JSON: %v; did you mean to use a config adapter (the --adapter flag)?", err)
		}
	}

	return config, configFile, nil
}

// watchConfigFile watches the config file at filename for changes
// and reloads the config if the file was updated. This function
// blocks indefinitely; it only quits if the poller has errors for
// long enough time. The filename passed in must be the actual
// config file used, not one to be discovered.
// Each second the config files is loaded and parsed into an object
// and is compared to the last config object that was loaded
func watchConfigFile(filename, adapterName string) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] watching config file: %v\n%s", err, debug.Stack())
		}
	}()

	// make our logger; since config reloads can change the
	// default logger, we need to get it dynamically each time
	logger := func() *zap.Logger {
		return caddy.Log().
			Named("watcher").
			With(zap.String("config_file", filename))
	}

	// get current config
	lastCfg, _, err := loadConfigWithLogger(nil, filename, adapterName)
	if err != nil {
		logger().Error("unable to load latest config", zap.Error(err))
		return
	}

	logger().Info("watching config file for changes")

	// begin poller
	//nolint:staticcheck
	for range time.Tick(1 * time.Second) {
		// get current config
		newCfg, _, err := loadConfigWithLogger(nil, filename, adapterName)
		if err != nil {
			logger().Error("unable to load latest config", zap.Error(err))
			return
		}

		// if it hasn't changed, nothing to do
		if bytes.Equal(lastCfg, newCfg) {
			continue
		}
		logger().Info("config file changed; reloading")

		// remember the current config
		lastCfg = newCfg

		// apply the updated config
		err = caddy.Load(lastCfg, false)
		if err != nil {
			logger().Error("applying latest config", zap.Error(err))
			continue
		}
	}
}

// Flags wraps a FlagSet so that typed values
// from flags can be easily retrieved.
type Flags struct {
	*pflag.FlagSet
}

// String returns the string representation of the
// flag given by name. It panics if the flag is not
// in the flag set.
func (f Flags) String(name string) string {
	return f.FlagSet.Lookup(name).Value.String()
}

// Bool returns the boolean representation of the
// flag given by name. It returns false if the flag
// is not a boolean type. It panics if the flag is
// not in the flag set.
func (f Flags) Bool(name string) bool {
	val, _ := strconv.ParseBool(f.String(name))
	return val
}

// Int returns the integer representation of the
// flag given by name. It returns 0 if the flag
// is not an integer type. It panics if the flag is
// not in the flag set.
func (f Flags) Int(name string) int {
	val, _ := strconv.ParseInt(f.String(name), 0, strconv.IntSize)
	return int(val)
}

// Float64 returns the float64 representation of the
// flag given by name. It returns false if the flag
// is not a float64 type. It panics if the flag is
// not in the flag set.
func (f Flags) Float64(name string) float64 {
	val, _ := strconv.ParseFloat(f.String(name), 64)
	return val
}

// Duration returns the duration representation of the
// flag given by name. It returns false if the flag
// is not a duration type. It panics if the flag is
// not in the flag set.
func (f Flags) Duration(name string) time.Duration {
	val, _ := caddy.ParseDuration(f.String(name))
	return val
}

func loadEnvFromFile(envFile string) error {
	file, err := os.Open(envFile)
	if err != nil {
		return fmt.Errorf("reading environment file: %v", err)
	}
	defer file.Close()

	envMap, err := parseEnvFile(file)
	if err != nil {
		return fmt.Errorf("parsing environment file: %v", err)
	}

	for k, v := range envMap {
		// do not overwrite existing environment variables
		_, exists := os.LookupEnv(k)
		if !exists {
			if err := os.Setenv(k, v); err != nil {
				return fmt.Errorf("setting environment variables: %v", err)
			}
		}
	}

	// Update the storage paths to ensure they have the proper
	// value after loading a specified env file.
	caddy.ConfigAutosavePath = filepath.Join(caddy.AppConfigDir(), "autosave.json")
	caddy.DefaultStorage = &certmagic.FileStorage{Path: caddy.AppDataDir()}

	return nil
}

// parseEnvFile parses an env file from KEY=VALUE format.
// It's pretty naive. Limited value quotation is supported,
// but variable and command expansions are not supported.
func parseEnvFile(envInput io.Reader) (map[string]string, error) {
	envMap := make(map[string]string)

	scanner := bufio.NewScanner(envInput)
	var lineNumber int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNumber++

		// skip empty lines and lines starting with comment
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// split line into key and value
		before, after, isCut := strings.Cut(line, "=")
		if !isCut {
			return nil, fmt.Errorf("can't parse line %d; line should be in KEY=VALUE format", lineNumber)
		}
		key, val := before, after

		// sometimes keys are prefixed by "export " so file can be sourced in bash; ignore it here
		key = strings.TrimPrefix(key, "export ")

		// validate key and value
		if key == "" {
			return nil, fmt.Errorf("missing or empty key on line %d", lineNumber)
		}
		if strings.Contains(key, " ") {
			return nil, fmt.Errorf("invalid key on line %d: contains whitespace: %s", lineNumber, key)
		}
		if strings.HasPrefix(val, " ") || strings.HasPrefix(val, "\t") {
			return nil, fmt.Errorf("invalid value on line %d: whitespace before value: '%s'", lineNumber, val)
		}

		// remove any trailing comment after value
		if commentStart, _, found := strings.Cut(val, "#"); found {
			val = strings.TrimRight(commentStart, " \t")
		}

		// quoted value: support newlines
		if strings.HasPrefix(val, `"`) || strings.HasPrefix(val, "'") {
			quote := string(val[0])
			for !(strings.HasSuffix(line, quote) && !strings.HasSuffix(line, `\`+quote)) {
				val = strings.ReplaceAll(val, `\`+quote, quote)
				if !scanner.Scan() {
					break
				}
				lineNumber++
				line = strings.ReplaceAll(scanner.Text(), `\`+quote, quote)
				val += "\n" + line
			}
			val = strings.TrimPrefix(val, quote)
			val = strings.TrimSuffix(val, quote)
		}

		envMap[key] = val
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return envMap, nil
}

func printEnvironment() {
	_, version := caddy.Version()
	fmt.Printf("caddy.HomeDir=%s\n", caddy.HomeDir())
	fmt.Printf("caddy.AppDataDir=%s\n", caddy.AppDataDir())
	fmt.Printf("caddy.AppConfigDir=%s\n", caddy.AppConfigDir())
	fmt.Printf("caddy.ConfigAutosavePath=%s\n", caddy.ConfigAutosavePath)
	fmt.Printf("caddy.Version=%s\n", version)
	fmt.Printf("runtime.GOOS=%s\n", runtime.GOOS)
	fmt.Printf("runtime.GOARCH=%s\n", runtime.GOARCH)
	fmt.Printf("runtime.Compiler=%s\n", runtime.Compiler)
	fmt.Printf("runtime.NumCPU=%d\n", runtime.NumCPU())
	fmt.Printf("runtime.GOMAXPROCS=%d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("runtime.Version=%s\n", runtime.Version())
	cwd, err := os.Getwd()
	if err != nil {
		cwd = fmt.Sprintf("<error: %v>", err)
	}
	fmt.Printf("os.Getwd=%s\n\n", cwd)
	for _, v := range os.Environ() {
		fmt.Println(v)
	}
}

// StringSlice is a flag.Value that enables repeated use of a string flag.
type StringSlice []string

func (ss StringSlice) String() string { return "[" + strings.Join(ss, ", ") + "]" }

func (ss *StringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

// Interface guard
var _ flag.Value = (*StringSlice)(nil)
