package caddytest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// Config store any configuration required to make the tests run
type Config struct {
	// Port we expect caddy to listening on
	AdminPort int
	// Certificates we expect to be loaded before attempting to run the tests
	Certificates []string
	// TestRequestTimeout is the time to wait for a http request to
	TestRequestTimeout time.Duration
	// LoadRequestTimeout is the time to wait for the config to be loaded against the caddy server
	LoadRequestTimeout time.Duration
}

// Default testing values
var Default = Config{
	Certificates:       []string{"/caddy.localhost.crt", "/caddy.localhost.key"},
	TestRequestTimeout: 5 * time.Second,
	LoadRequestTimeout: 5 * time.Second,
}

// Tester represents an instance of a test client.
type Tester struct {
	Client *http.Client

	portOne int
	portTwo int

	started        atomic.Bool
	configLoaded   bool
	configFileName string
	envFileName    string

	t      testing.TB
	config Config
}

// NewTester will create a new testing client with an attached cookie jar
func NewTester(t testing.TB) (*Tester, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookiejar: %w", err)
	}

	return &Tester{
		Client: &http.Client{
			Transport: CreateTestingTransport(),
			Jar:       jar,
			Timeout:   Default.TestRequestTimeout,
		},
		configLoaded: false,
		t:            t,
		config:       Default,
	}, nil
}

// WithDefaultOverrides this will override the default test configuration with the provided values.
func (tc *Tester) WithDefaultOverrides(overrides Config) *Tester {
	if overrides.AdminPort != 0 {
		tc.config.AdminPort = overrides.AdminPort
	}
	if len(overrides.Certificates) > 0 {
		tc.config.Certificates = overrides.Certificates
	}
	if overrides.TestRequestTimeout != 0 {
		tc.config.TestRequestTimeout = overrides.TestRequestTimeout
		tc.Client.Timeout = overrides.TestRequestTimeout
	}
	if overrides.LoadRequestTimeout != 0 {
		tc.config.LoadRequestTimeout = overrides.LoadRequestTimeout
	}

	return tc
}

type configLoadError struct {
	Response string
}

func (e configLoadError) Error() string { return e.Response }

func timeElapsed(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

// launch caddy will start the server
func (tc *Tester) LaunchCaddy() error {
	if !tc.started.CompareAndSwap(false, true) {
		return fmt.Errorf("already launched caddy with this tester")
	}
	if err := tc.startServer(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	return nil
}

func (tc *Tester) CleanupCaddy() error {
	// now shutdown the server, since the test is done.
	defer func() {
		// try to remove  pthe tmp config file we created
		if tc.configFileName != "" {
			os.Remove(tc.configFileName)
		}
		if tc.envFileName != "" {
			os.Remove(tc.envFileName)
		}

		if tc.t.Failed() && tc.configLoaded {
			res, err := http.Get(fmt.Sprintf("http://localhost:%d/config/", tc.config.AdminPort))
			if err != nil {
				tc.t.Log("unable to read the current config")
				return
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)

			var out bytes.Buffer
			_ = json.Indent(&out, body, "", "  ")
			tc.t.Logf("----------- failed with config -----------\n%s", out.String())
		}
	}()

	resp, err := http.Post(fmt.Sprintf("http://localhost:%d/stop", tc.config.AdminPort), "", nil)
	if err != nil {
		return fmt.Errorf("couldn't stop caddytest server: %w", err)
	}
	resp.Body.Close()
	for range 10 {
		if tc.isCaddyAdminRunning() != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timed out waiting for caddytest server to stop")
}

func (tc *Tester) AdminPort() int {
	return tc.config.AdminPort
}

func (tc *Tester) PortOne() int {
	return tc.portOne
}

func (tc *Tester) PortTwo() int {
	return tc.portTwo
}

func (tc *Tester) ReplaceTestingPlaceholders(x string) string {
	x = strings.ReplaceAll(x, "{$TESTING_CADDY_ADMIN_BIND}", fmt.Sprintf("localhost:%d", tc.config.AdminPort))
	x = strings.ReplaceAll(x, "{$TESTING_CADDY_ADMIN_PORT}", fmt.Sprintf("%d", tc.config.AdminPort))
	x = strings.ReplaceAll(x, "{$TESTING_CADDY_PORT_ONE}", fmt.Sprintf("%d", tc.portOne))
	x = strings.ReplaceAll(x, "{$TESTING_CADDY_PORT_TWO}", fmt.Sprintf("%d", tc.portTwo))
	return x
}

// LoadConfig loads the config to the tester server and also ensures that the config was loaded
// it should not be run
func (tc *Tester) LoadConfig(rawConfig string, configType string) error {
	if tc.config.AdminPort == 0 {
		return fmt.Errorf("load config called where startServer didnt succeed")
	}

	rawConfig = tc.ReplaceTestingPlaceholders(rawConfig)
	// replace special testing placeholders so we can have our admin api be on a random port
	// normalize JSON config
	if configType == "json" {
		tc.t.Logf("Before: %s", rawConfig)
		var conf any
		if err := json.Unmarshal([]byte(rawConfig), &conf); err != nil {
			return err
		}
		c, err := json.Marshal(conf)
		if err != nil {
			return err
		}
		rawConfig = string(c)
		tc.t.Logf("After: %s", rawConfig)
	}
	client := &http.Client{
		Timeout: tc.config.LoadRequestTimeout,
	}
	start := time.Now()
	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/load", tc.config.AdminPort), strings.NewReader(rawConfig))
	if err != nil {
		return fmt.Errorf("failed to create request. %w", err)
	}

	if configType == "json" {
		req.Header.Add("Content-Type", "application/json")
	} else {
		req.Header.Add("Content-Type", "text/"+configType)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to contact caddy server. %w", err)
	}
	timeElapsed(start, "caddytest: config load time")

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("unable to read response. %w", err)
	}

	if res.StatusCode != 200 {
		return configLoadError{Response: string(body)}
	}

	tc.configLoaded = true

	// if the config is not loaded at this point, it is a bug in caddy's config.Load
	// the contract for config.Load states that the config must be loaded before it returns, and that it will
	// error if the config fails to apply
	return nil
}

func (tc *Tester) GetCurrentConfig(receiver any) error {
	client := &http.Client{
		Timeout: tc.config.LoadRequestTimeout,
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/config/", tc.config.AdminPort))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	actualBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(actualBytes, &receiver)
	if err != nil {
		return nil
	}
	return nil
}

func getFreePort() (int, error) {
	lr, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	port := strings.Split(lr.Addr().String(), ":")
	if len(port) < 2 {
		return 0, fmt.Errorf("no port available")
	}
	i, err := strconv.Atoi(port[1])
	if err != nil {
		return 0, err
	}
	err = lr.Close()
	if err != nil {
		return 0, fmt.Errorf("failed to close listener: %w", err)
	}
	return i, nil
}

// launches caddy, and then ensures the Caddy sub-process is running.
func (tc *Tester) startServer() error {
	if tc.isCaddyAdminRunning() == nil {
		return fmt.Errorf("caddy test admin port still in use")
	}
	a, err := getFreePort()
	if err != nil {
		return fmt.Errorf("could not find a open port to listen on: %w", err)
	}
	tc.config.AdminPort = a
	tc.portOne, err = getFreePort()
	if err != nil {
		return fmt.Errorf("could not find a open portOne: %w", err)
	}
	tc.portTwo, err = getFreePort()
	if err != nil {
		return fmt.Errorf("could not find a open portOne: %w", err)
	}
	// setup the init config file, and set the cleanup afterwards
	{
		f, err := os.CreateTemp("", "")
		if err != nil {
			return err
		}
		tc.configFileName = f.Name()

		initConfig := `{
	admin localhost:%d
}`
		if _, err := fmt.Fprintf(f, initConfig, tc.config.AdminPort); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	// start inprocess caddy server
	go func() {
		_ = caddycmd.MainForTesting("run", "--config", tc.configFileName, "--adapter", "caddyfile")
	}()
	// wait for caddy admin api to start. it should happen quickly.
	for retries := 10; retries > 0 && tc.isCaddyAdminRunning() != nil; retries-- {
		time.Sleep(100 * time.Millisecond)
	}

	// one more time to return the error
	return tc.isCaddyAdminRunning()
}
func (tc *Tester) isCaddyAdminRunning() error {
	// assert that caddy is running
	client := &http.Client{
		Timeout: Default.LoadRequestTimeout,
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/config/", tc.config.AdminPort))
	if err != nil {
		return fmt.Errorf("caddy integration test caddy server not running. Expected to be listening on localhost:%d", tc.config.AdminPort)
	}
	resp.Body.Close()

	return nil
}

// CreateTestingTransport creates a testing transport that forces call dialing connections to happen locally
func CreateTestingTransport() *http.Transport {
	dialer := net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
		DualStack: true,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		parts := strings.Split(addr, ":")
		destAddr := fmt.Sprintf("127.0.0.1:%s", parts[1])
		log.Printf("caddytest: redirecting the dialer from %s to %s", addr, destAddr)
		return dialer.DialContext(ctx, network, destAddr)
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
}
