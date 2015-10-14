package middleware

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInclude(t *testing.T) {
	context := initTempContext()

	inputFilename := "test_file"
	absInFilePath := filepath.Join(fmt.Sprintf("%s", context.Root), inputFilename)
	defer func() {
		err := os.Remove(absInFilePath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("Failed to clean test file!")
		}
	}()

	tests := []struct {
		fileContent          string
		expectedContent      string
		shouldErr            bool
		expectedErrorContent string
	}{
		// Test 0 - all good
		{
			fileContent:          `str1 {{ .Root }} str2`,
			expectedContent:      fmt.Sprintf("str1 %s str2", context.Root),
			shouldErr:            false,
			expectedErrorContent: "",
		},
		// Test 1 - failure on template.Parse
		{
			fileContent:          `str1 {{ .Root } str2`,
			expectedContent:      "",
			shouldErr:            true,
			expectedErrorContent: `unexpected "}" in operand`,
		},
		// Test 3 - failure on template.Execute
		{
			fileContent:          `str1 {{ .InvalidField }} str2`,
			expectedContent:      "",
			shouldErr:            false,
			expectedErrorContent: `InvalidField is not a field of struct type middleware.Context`,
		},
	}

	for i, test := range tests {
		testPrefix := fmt.Sprintf("Test [%d]: ", i)

		// WriteFile truncates the contentt
		err := ioutil.WriteFile(absInFilePath, []byte(test.fileContent), os.ModePerm)
		if err != nil {
			t.Fatal(testPrefix+"Failed to create test file. Error was: %v", err)
		}

		content, err := context.Include(inputFilename)
		if err != nil {
			if !strings.Contains(err.Error(), test.expectedErrorContent) {
				t.Errorf(testPrefix+"Expected error content [%s], found [%s]", test.expectedErrorContent, err.Error())
			}
		}

		if err == nil && test.shouldErr {
			t.Errorf(testPrefix+"Expected error [%s] but found nil. Input file was: %s", test.expectedErrorContent, inputFilename)
		}

		if content != test.expectedContent {
			t.Errorf(testPrefix+"Expected content [%s] but found [%s]. Input file was: %s", test.expectedContent, content, inputFilename)
		}
	}
}

func TestIncludeNotExisting(t *testing.T) {
	context := initTempContext()

	_, err := context.Include("not_existing")
	if err == nil {
		t.Errorf("Expected error but found nil!")
	}
}

func initTempContext() Context {
	rootDir := getTestFilesFolder()
	return Context{Root: http.Dir(rootDir)}
}

func getTestFilesFolder() string {
	return os.TempDir()
}
