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

package caddy

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestParseUnixCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		// 0 - empty command
		{
			input:    ``,
			expected: []string{},
		},
		// 1 - command without arguments
		{
			input:    `command`,
			expected: []string{`command`},
		},
		// 2 - command with single argument
		{
			input:    `command arg1`,
			expected: []string{`command`, `arg1`},
		},
		// 3 - command with multiple arguments
		{
			input:    `command arg1 arg2`,
			expected: []string{`command`, `arg1`, `arg2`},
		},
		// 4 - command with single argument with space character - in quotes
		{
			input:    `command "arg1 arg1"`,
			expected: []string{`command`, `arg1 arg1`},
		},
		// 5 - command with multiple spaces and tab character
		{
			input:    "command arg1    arg2\targ3",
			expected: []string{`command`, `arg1`, `arg2`, `arg3`},
		},
		// 6 - command with single argument with space character - escaped with backspace
		{
			input:    `command arg1\ arg2`,
			expected: []string{`command`, `arg1 arg2`},
		},
		// 7 - single quotes should escape special chars
		{
			input:    `command 'arg1\ arg2'`,
			expected: []string{`command`, `arg1\ arg2`},
		},
	}

	for i, test := range tests {
		errorPrefix := fmt.Sprintf("Test [%d]: ", i)
		errorSuffix := fmt.Sprintf(" Command to parse: [%s]", test.input)
		actual, _ := parseUnixCommand(test.input)
		if len(actual) != len(test.expected) {
			t.Errorf(errorPrefix+"Expected %d parts, got %d: %#v."+errorSuffix, len(test.expected), len(actual), actual)
			continue
		}
		for j := 0; j < len(actual); j++ {
			if expectedPart, actualPart := test.expected[j], actual[j]; expectedPart != actualPart {
				t.Errorf(errorPrefix+"Expected: %v Actual: %v (index %d)."+errorSuffix, expectedPart, actualPart, j)
			}
		}
	}
}

func TestParseWindowsCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{ // 0 - empty command - do not fail
			input:    ``,
			expected: []string{},
		},
		{ // 1 - cmd without args
			input:    `cmd`,
			expected: []string{`cmd`},
		},
		{ // 2 - multiple args
			input:    `cmd arg1 arg2`,
			expected: []string{`cmd`, `arg1`, `arg2`},
		},
		{ // 3 - multiple args with space
			input:    `cmd "combined arg" arg2`,
			expected: []string{`cmd`, `combined arg`, `arg2`},
		},
		{ // 4 - path without spaces
			input:    `mkdir C:\Windows\foo\bar`,
			expected: []string{`mkdir`, `C:\Windows\foo\bar`},
		},
		{ // 5 - command with space in quotes
			input:    `"command here"`,
			expected: []string{`command here`},
		},
		{ // 6 - argument with escaped quotes (two quotes)
			input:    `cmd ""arg""`,
			expected: []string{`cmd`, `"arg"`},
		},
		{ // 7 - argument with escaped quotes (backslash)
			input:    `cmd \"arg\"`,
			expected: []string{`cmd`, `"arg"`},
		},
		{ // 8 - two quotes (escaped) inside an inQuote element
			input:    `cmd "a ""quoted value"`,
			expected: []string{`cmd`, `a "quoted value`},
		},
		// TODO - see how many quotes are displayed if we use "", """, """""""
		{ // 9 - two quotes outside an inQuote element
			input:    `cmd a ""quoted value`,
			expected: []string{`cmd`, `a`, `"quoted`, `value`},
		},
		{ // 10 - path with space in quotes
			input:    `mkdir "C:\directory name\foobar"`,
			expected: []string{`mkdir`, `C:\directory name\foobar`},
		},
		{ // 11 - space without quotes
			input:    `mkdir C:\ space`,
			expected: []string{`mkdir`, `C:\`, `space`},
		},
		{ // 12 - space in quotes
			input:    `mkdir "C:\ space"`,
			expected: []string{`mkdir`, `C:\ space`},
		},
		{ // 13 - UNC
			input:    `mkdir \\?\C:\Users`,
			expected: []string{`mkdir`, `\\?\C:\Users`},
		},
		{ // 14 - UNC with space
			input:    `mkdir "\\?\C:\Program Files"`,
			expected: []string{`mkdir`, `\\?\C:\Program Files`},
		},

		{ // 15 - unclosed quotes - treat as if the path ends with quote
			input:    `mkdir "c:\Program files`,
			expected: []string{`mkdir`, `c:\Program files`},
		},
		{ // 16 - quotes used inside the argument
			input:    `mkdir "c:\P"rogra"m f"iles`,
			expected: []string{`mkdir`, `c:\Program files`},
		},
	}

	for i, test := range tests {
		errorPrefix := fmt.Sprintf("Test [%d]: ", i)
		errorSuffix := fmt.Sprintf(" Command to parse: [%s]", test.input)

		actual := parseWindowsCommand(test.input)
		if len(actual) != len(test.expected) {
			t.Errorf(errorPrefix+"Expected %d parts, got %d: %#v."+errorSuffix, len(test.expected), len(actual), actual)
			continue
		}
		for j := 0; j < len(actual); j++ {
			if expectedPart, actualPart := test.expected[j], actual[j]; expectedPart != actualPart {
				t.Errorf(errorPrefix+"Expected: %v Actual: %v (index %d)."+errorSuffix, expectedPart, actualPart, j)
			}
		}
	}
}

func TestSplitCommandAndArgs(t *testing.T) {

	// force linux parsing. It's more robust and covers error cases
	runtimeGoos = "linux"
	defer func() {
		runtimeGoos = runtime.GOOS
	}()

	var parseErrorContent = "error parsing command:"
	var noCommandErrContent = "no command contained in"

	tests := []struct {
		input              string
		expectedCommand    string
		expectedArgs       []string
		expectedErrContent string
	}{
		// 0 - empty command
		{
			input:              ``,
			expectedCommand:    ``,
			expectedArgs:       nil,
			expectedErrContent: noCommandErrContent,
		},
		// 1 - command without arguments
		{
			input:              `command`,
			expectedCommand:    `command`,
			expectedArgs:       nil,
			expectedErrContent: ``,
		},
		// 2 - command with single argument
		{
			input:              `command arg1`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`},
			expectedErrContent: ``,
		},
		// 3 - command with multiple arguments
		{
			input:              `command arg1 arg2`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`, `arg2`},
			expectedErrContent: ``,
		},
		// 4 - command with unclosed quotes
		{
			input:              `command "arg1 arg2`,
			expectedCommand:    "",
			expectedArgs:       nil,
			expectedErrContent: parseErrorContent,
		},
		// 5 - command with unclosed quotes
		{
			input:              `command 'arg1 arg2"`,
			expectedCommand:    "",
			expectedArgs:       nil,
			expectedErrContent: parseErrorContent,
		},
	}

	for i, test := range tests {
		errorPrefix := fmt.Sprintf("Test [%d]: ", i)
		errorSuffix := fmt.Sprintf(" Command to parse: [%s]", test.input)
		actualCommand, actualArgs, actualErr := SplitCommandAndArgs(test.input)

		// test if error matches expectation
		if test.expectedErrContent != "" {
			if actualErr == nil {
				t.Errorf(errorPrefix+"Expected error with content [%s], found no error."+errorSuffix, test.expectedErrContent)
			} else if !strings.Contains(actualErr.Error(), test.expectedErrContent) {
				t.Errorf(errorPrefix+"Expected error with content [%s], found [%v]."+errorSuffix, test.expectedErrContent, actualErr)
			}
		} else if actualErr != nil {
			t.Errorf(errorPrefix+"Expected no error, found [%v]."+errorSuffix, actualErr)
		}

		// test if command matches
		if test.expectedCommand != actualCommand {
			t.Errorf(errorPrefix+"Expected command: [%s], actual: [%s]."+errorSuffix, test.expectedCommand, actualCommand)
		}

		// test if arguments match
		if len(test.expectedArgs) != len(actualArgs) {
			t.Errorf(errorPrefix+"Wrong number of arguments! Expected [%v], actual [%v]."+errorSuffix, test.expectedArgs, actualArgs)
		} else {
			// test args only if the count matches.
			for j, actualArg := range actualArgs {
				expectedArg := test.expectedArgs[j]
				if actualArg != expectedArg {
					t.Errorf(errorPrefix+"Argument at position [%d] differ! Expected [%s], actual [%s]"+errorSuffix, j, expectedArg, actualArg)
				}
			}
		}
	}
}

func ExampleSplitCommandAndArgs() {
	var commandLine string
	var command string
	var args []string

	// just for the test - change GOOS and reset it at the end of the test
	runtimeGoos = "windows"
	defer func() {
		runtimeGoos = runtime.GOOS
	}()

	commandLine = `mkdir /P "C:\Program Files"`
	command, args, _ = SplitCommandAndArgs(commandLine)

	fmt.Printf("Windows: %s: %s [%s]\n", commandLine, command, strings.Join(args, ","))

	// set GOOS to linux
	runtimeGoos = "linux"

	commandLine = `mkdir -p /path/with\ space`
	command, args, _ = SplitCommandAndArgs(commandLine)

	fmt.Printf("Linux: %s: %s [%s]\n", commandLine, command, strings.Join(args, ","))

	// Output:
	// Windows: mkdir /P "C:\Program Files": mkdir [/P,C:\Program Files]
	// Linux: mkdir -p /path/with\ space: mkdir [-p,/path/with space]
}
