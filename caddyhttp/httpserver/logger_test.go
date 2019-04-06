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

//+build linux darwin

package httpserver

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	syslog "gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/mcuadros/go-syslog.v2/format"
)

func TestLoggingToStdout(t *testing.T) {
	testCases := []struct {
		Output         string
		ExpectedOutput string
	}{
		{
			Output:         "stdout",
			ExpectedOutput: "Hello world logged to stdout",
		},
	}

	for i, testCase := range testCases {
		output := captureStdout(func() {
			logger := Logger{Output: testCase.Output, fileMu: new(sync.RWMutex)}

			if err := logger.Start(); err != nil {
				t.Fatalf("Got unexpected error: %v", err)
			}

			logger.Println(testCase.ExpectedOutput)
		})

		if !strings.Contains(output, testCase.ExpectedOutput) {
			t.Fatalf("Test #%d: Expected output to contain: %s, got: %s", i, testCase.ExpectedOutput, output)
		}
	}
}

func TestLoggingToStderr(t *testing.T) {

	testCases := []struct {
		Output         string
		ExpectedOutput string
	}{
		{
			Output:         "stderr",
			ExpectedOutput: "Hello world logged to stderr",
		},
		{
			Output:         "",
			ExpectedOutput: "Hello world logged to stderr #2",
		},
	}

	for i, testCase := range testCases {
		output := captureStderr(func() {
			logger := Logger{Output: testCase.Output, fileMu: new(sync.RWMutex)}

			if err := logger.Start(); err != nil {
				t.Fatalf("Got unexpected error: %v", err)
			}

			logger.Println(testCase.ExpectedOutput)
		})

		if !strings.Contains(output, testCase.ExpectedOutput) {
			t.Fatalf("Test #%d: Expected output to contain: %s, got: %s", i, testCase.ExpectedOutput, output)
		}
	}
}

func TestLoggingToFile(t *testing.T) {
	file := filepath.Join(os.TempDir(), "access.log")
	expectedOutput := "Hello world written to file"

	logger := Logger{Output: file}

	if err := logger.Start(); err != nil {
		t.Fatalf("Got unexpected error during logger start: %v", err)
	}

	logger.Print(expectedOutput)

	content, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatalf("Could not read log file content: %v", err)
	}

	if !bytes.Contains(content, []byte(expectedOutput)) {
		t.Fatalf("Expected log file to contain: %s, got: %s", expectedOutput, string(content))
	}

	os.Remove(file)
}

func TestLoggingToSyslog(t *testing.T) {

	testCases := []struct {
		Output         string
		ExpectedOutput string
	}{
		{
			Output:         "syslog://127.0.0.1:5660",
			ExpectedOutput: "Hello world! Test #1 over tcp",
		},
		{
			Output:         "syslog+tcp://127.0.0.1:5661",
			ExpectedOutput: "Hello world! Test #2 over tcp",
		},
		{
			Output:         "syslog+udp://127.0.0.1:5662",
			ExpectedOutput: "Hello world! Test #3 over udp",
		},
	}

	for i, testCase := range testCases {

		ch := make(chan format.LogParts, 256)
		server, err := bootServer(testCase.Output, ch)
		defer server.Kill()

		if err != nil {
			t.Errorf("Test #%d: expected no error during syslog server boot, got: %v", i, err)
		}

		logger := Logger{Output: testCase.Output, fileMu: new(sync.RWMutex)}

		if err := logger.Start(); err != nil {
			t.Errorf("Test #%d: expected no error during logger start, got: %v", i, err)
		}

		defer logger.Close()

		logger.Print(testCase.ExpectedOutput)

		actual := <-ch

		if content, ok := actual["content"].(string); ok {
			if !strings.Contains(content, testCase.ExpectedOutput) {
				t.Errorf("Test #%d: expected server to capture content: %s, but got: %s", i, testCase.ExpectedOutput, content)
			}
		} else {
			t.Errorf("Test #%d: expected server to capture content but got: %v", i, actual)
		}
	}
}

func bootServer(location string, ch chan format.LogParts) (*syslog.Server, error) {
	address := parseSyslogAddress(location)

	if address == nil {
		return nil, fmt.Errorf("Could not parse syslog address: %s", location)
	}

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)

	switch address.network {
	case "tcp":
		if err := server.ListenTCP(address.address); err != nil {
			log.Println("[ERROR] server failed to listen on TCP address: ", err)
		}
	case "udp":
		if err := server.ListenUDP(address.address); err != nil {
			log.Println("[ERROR] server failed to listen on UDP address: ", err)
		}
	}

	server.SetHandler(syslog.NewChannelHandler(ch))

	if err := server.Boot(); err != nil {
		return nil, err
	}

	return server, nil
}

func captureStdout(f func()) string {
	original := os.Stdout
	r, w, _ := os.Pipe()

	os.Stdout = w

	f()

	w.Close()

	written, _ := ioutil.ReadAll(r)
	os.Stdout = original

	return string(written)
}

func captureStderr(f func()) string {
	original := os.Stderr
	r, w, _ := os.Pipe()

	os.Stderr = w

	f()

	w.Close()

	written, _ := ioutil.ReadAll(r)
	os.Stderr = original

	return string(written)
}
