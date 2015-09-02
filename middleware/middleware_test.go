package middleware

import (
	"net/http"
	"testing"
)

func TestIndexfile(t *testing.T) {
	tests := []struct {
		rootDir           http.FileSystem
		fpath             string
		indexFiles        []string
		shouldErr         bool
		expectedFilePath  string //retun value
		expectedBoolValue bool   //return value
	}{
		{
			http.Dir("./templates/testdata"), "/images/", []string{"img.htm"},
			false,
			"/images/img.htm", true,
		},
	}
	for i, test := range tests {
		actualFilePath, actualBoolValue := IndexFile(test.rootDir, test.fpath, test.indexFiles)
		if actualBoolValue == true && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if actualBoolValue != true && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got %s", i, "Please Add a / at the end of fpath or the indexFiles doesnt exist")
		}
		if actualFilePath != test.expectedFilePath {
			t.Fatalf("Test %d expected returned filepath to be %s, but got %s ",
				i, test.expectedFilePath, actualFilePath)

		}
		if actualBoolValue != test.expectedBoolValue {
			t.Fatalf("Test %d expected returned bool value to be %v, but got %v ",
				i, test.expectedBoolValue, actualBoolValue)

		}
	}
}
