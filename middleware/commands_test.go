package middleware

import (
	"fmt"
	"strings"
	"testing"
)

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
		// Test case 4 - command with single argument with space character - escaped
		{
			input:              `command arg1\ arg1`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1 arg1`},
			expectedErrContent: ``,
		},
		// Test case 6 - command with escaped quote character
		{
			input:              `command "arg1 \" arg1"`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1 " arg1`},
			expectedErrContent: ``,
		},
		// Test case 7 - command with escaped backslash
		{
			input:              `command '\arg1'`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`\arg1`},
			expectedErrContent: ``,
		},
		// Test case 8 - command with comments
		{
			input:              `command arg1 #comment1 comment2`,
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`},
			expectedErrContent: "",
		},
		// Test case 9 - command with multiple spaces and tab character
		{
			input:              "command arg1    arg2\targ3",
			expectedCommand:    `command`,
			expectedArgs:       []string{`arg1`, `arg2`, "arg3"},
			expectedErrContent: "",
		},
		// Test case 10 - command with unclosed quotes
		{
			input:              `command "arg1 arg2`,
			expectedCommand:    "",
			expectedArgs:       nil,
			expectedErrContent: parseErrorContent,
		},
		// Test case 11 - command with unclosed quotes
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
