package middleware

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseWindowsCommand(t *testing.T) {
	for i, test := range []struct {
		input    string
		expected []string
	}{
		{ // 0
			input:    `cmd`,
			expected: []string{`cmd`},
		},
		{ // 1
			input:    `cmd arg1 arg2`,
			expected: []string{`cmd`, `arg1`, `arg2`},
		},
		{ // 2
			input:    `cmd "combined arg" arg2`,
			expected: []string{`cmd`, `combined arg`, `arg2`},
		},
		{ // 3
			input:    `mkdir C:\Windows\foo\bar`,
			expected: []string{`mkdir`, `C:\Windows\foo\bar`},
		},
		{ // 4
			input:    `"command here"`,
			expected: []string{`command here`},
		},
		{ // 5
			input:    `cmd \"arg\"`,
			expected: []string{`cmd`, `"arg"`},
		},
		{ // 6
			input:    `cmd "a \"quoted value\""`,
			expected: []string{`cmd`, `a "quoted value"`},
		},
		{ // 7
			input:    `mkdir "C:\directory name\foobar"`,
			expected: []string{`mkdir`, `C:\directory name\foobar`},
		},
		{ // 8
			input:    `mkdir C:\ space`,
			expected: []string{`mkdir`, `C:\`, `space`},
		},
		{ // 9
			input:    `mkdir "C:\ space"`,
			expected: []string{`mkdir`, `C:\ space`},
		},
		{ // 10
			input:    `\\"`,
			expected: []string{`\`},
		},
		{ // 11
			input:    `"\\\""`,
			expected: []string{`\"`},
		},
	} {
		actual := parseWindowsCommand(test.input)
		if len(actual) != len(test.expected) {
			t.Errorf("Test %d: Expected %d parts, got %d: %#v", i, len(test.expected), len(actual), actual)
			continue
		}
		for j := 0; j < len(actual); j++ {
			if expectedPart, actualPart := test.expected[j], actual[j]; expectedPart != actualPart {
				t.Errorf("Test %d: Expected: %v Actual: %v (index %d)", i, expectedPart, actualPart, j)
			}
		}
	}
}

func TestSplitCommandAndArgs(t *testing.T) {
	var parseErrorContent = "error parsing command:"
	var noCommandErrContent = "no command contained in"

	tests := []struct {
		input              string
		expectedCommand    string
		expectedArgs       []string
		expectedErrContent string
	}{
		// Test case 0 - emtpy command
		{
			input:              ``,
			expectedCommand:    ``,
			expectedArgs:       nil,
			expectedErrContent: noCommandErrContent,
		},
		// Test case 1 - command without arguments
		{
			input:              `command`,
			expectedCommand:    `command`,
			expectedArgs:       nil,
			expectedErrContent: ``,
		},
		// Test case 2 - command with single argument
		{
			input:              `command arg1`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`},
			expectedErrContent: ``,
		},
		// Test case 3 - command with multiple arguments
		{
			input:              `command arg1 arg2`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`, `arg2`},
			expectedErrContent: ``,
		},
		// Test case 4 - command with single argument with space character - in quotes
		{
			input:              `command "arg1 arg1"`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1 arg1`},
			expectedErrContent: ``,
		},
		// Test case 5 - command with comments
		{
			input:              `command arg1 #comment1 comment2`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`},
			expectedErrContent: "",
		},
		// Test case 6 - command with multiple spaces and tab character
		{
			input:              "command arg1    arg2\targ3",
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`, `arg2`, "arg3"},
			expectedErrContent: "",
		},
		// Test case 7 - command with unclosed quotes
		{
			input:              `command "arg1 arg2`,
			expectedCommand:    "",
			expectedArgs:       nil,
			expectedErrContent: parseErrorContent,
		},
		// Test case 8 - command with unclosed quotes
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
			t.Errorf("Expected command: [%s], actual: [%s]."+errorSuffix, test.expectedCommand, actualCommand)
		}

		// test if arguments match
		if len(test.expectedArgs) != len(actualArgs) {
			t.Errorf("Wrong number of arguments! Expected [%v], actual [%v]."+errorSuffix, test.expectedArgs, actualArgs)
		}

		for j, actualArg := range actualArgs {
			expectedArg := test.expectedArgs[j]
			if actualArg != expectedArg {
				t.Errorf(errorPrefix+"Argument at position [%d] differ! Expected [%s], actual [%s]"+errorSuffix, j, expectedArg, actualArg)
			}
		}
	}
}
