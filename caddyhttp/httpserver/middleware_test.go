package httpserver

import (
	"os"
	"testing"
)

func TestPathCaseSensitivity(t *testing.T) {
	tests := []struct {
		basePath      string
		path          string
		caseSensitive bool
		expected      bool
	}{
		{"/", "/file", true, true},
		{"/a", "/file", true, false},
		{"/f", "/file", true, true},
		{"/f", "/File", true, false},
		{"/f", "/File", false, true},
		{"/file", "/file", true, true},
		{"/file", "/file", false, true},
		{"/files", "/file", false, false},
		{"/files", "/file", true, false},
		{"/folder", "/folder/file.txt", true, true},
		{"/folders", "/folder/file.txt", true, false},
		{"/folder", "/Folder/file.txt", false, true},
		{"/folders", "/Folder/file.txt", false, false},
	}

	for i, test := range tests {
		CaseSensitivePath = test.caseSensitive
		valid := Path(test.path).Matches(test.basePath)
		if test.expected != valid {
			t.Errorf("Test %d: Expected %v, found %v", i, test.expected, valid)
		}
	}
}

func TestPathCaseSensitiveEnv(t *testing.T) {
	tests := []struct {
		envValue string
		expected bool
	}{
		{"1", true},
		{"0", false},
		{"false", false},
		{"true", true},
		{"", true},
	}

	for i, test := range tests {
		os.Setenv(caseSensitivePathEnv, test.envValue)
		initCaseSettings()
		if test.expected != CaseSensitivePath {
			t.Errorf("Test %d: Expected %v, found %v", i, test.expected, CaseSensitivePath)
		}
	}
}
