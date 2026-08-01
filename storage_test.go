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

package caddy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func TestHomeDir_CrossPlatform(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"HOME":        os.Getenv("HOME"),
		"HOMEDRIVE":   os.Getenv("HOMEDRIVE"),
		"HOMEPATH":    os.Getenv("HOMEPATH"),
		"USERPROFILE": os.Getenv("USERPROFILE"),
		"home":        os.Getenv("home"), // Plan9
	}
	defer func() {
		// Restore environment
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	tests := []struct {
		name      string
		skipOS    []string
		envVars   map[string]string // Environment variables to set
		unsetVars []string          // Environment variables to unset
		expected  string
	}{
		{
			name:   "normal HOME set",
			skipOS: []string{"windows"}, // Skip on Windows - HOME isn't typically used on Windows
			envVars: map[string]string{
				"HOME": "/home/user",
			},
			unsetVars: []string{"HOMEDRIVE", "HOMEPATH", "USERPROFILE", "home"},
			expected:  "/home/user",
		},
		{
			name:      "no environment variables",
			unsetVars: []string{"HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "home"},
			expected:  ".", // Fallback to current directory
		},
	}

	// Windows-specific tests
	windowsTests := []struct {
		name      string
		envVars   map[string]string
		unsetVars []string
		expected  string
	}{
		{
			name: "windows HOMEDRIVE and HOMEPATH",
			envVars: map[string]string{
				"HOMEDRIVE": "C:",
				"HOMEPATH":  "\\Users\\user",
			},
			unsetVars: []string{"HOME", "USERPROFILE", "home"},
			expected:  "C:\\Users\\user",
		},
		{
			name: "windows USERPROFILE",
			envVars: map[string]string{
				"USERPROFILE": "C:\\Users\\user",
			},
			unsetVars: []string{"HOME", "HOMEDRIVE", "HOMEPATH", "home"},
			expected:  "C:\\Users\\user",
		},
	}

	// Plan9-specific tests
	plan9Tests := []struct {
		name      string
		envVars   map[string]string
		unsetVars []string
		expected  string
	}{
		{
			name: "plan9 home variable",
			envVars: map[string]string{
				"home": "/usr/user",
			},
			unsetVars: []string{"HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE"},
			expected:  "/usr/user",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Check if we should skip this test on current OS
			for _, skipOS := range test.skipOS {
				if runtime.GOOS == skipOS {
					t.Skipf("Skipping test on %s", skipOS)
				}
			}

			// Set up environment for this test
			for key, value := range test.envVars {
				os.Setenv(key, value)
			}
			for _, key := range test.unsetVars {
				os.Unsetenv(key)
			}

			result := HomeDir()

			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}

			// HomeDir should never return empty string
			if result == "" {
				t.Error("HomeDir should never return empty string")
			}
		})
	}

	// Run Windows-specific tests only on Windows
	if runtime.GOOS == "windows" {
		for _, test := range windowsTests {
			t.Run(test.name, func(t *testing.T) {
				for key, value := range test.envVars {
					os.Setenv(key, value)
				}
				for _, key := range test.unsetVars {
					os.Unsetenv(key)
				}

				result := HomeDir()

				if result != test.expected {
					t.Errorf("Expected '%s', got '%s'", test.expected, result)
				}
			})
		}
	}

	// Run Plan9-specific tests only on Plan9
	if runtime.GOOS == "plan9" {
		for _, test := range plan9Tests {
			t.Run(test.name, func(t *testing.T) {
				for key, value := range test.envVars {
					os.Setenv(key, value)
				}
				for _, key := range test.unsetVars {
					os.Unsetenv(key)
				}

				result := HomeDir()

				if result != test.expected {
					t.Errorf("Expected '%s', got '%s'", test.expected, result)
				}
			})
		}
	}
}

func TestHomeDirUnsafe_EdgeCases(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"HOME":        os.Getenv("HOME"),
		"HOMEDRIVE":   os.Getenv("HOMEDRIVE"),
		"HOMEPATH":    os.Getenv("HOMEPATH"),
		"USERPROFILE": os.Getenv("USERPROFILE"),
		"home":        os.Getenv("home"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	tests := []struct {
		name      string
		envVars   map[string]string
		unsetVars []string
		expected  string
	}{
		{
			name:      "no environment variables",
			unsetVars: []string{"HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "home"},
			expected:  "", // homeDirUnsafe can return empty
		},
		{
			name: "windows with incomplete HOMEDRIVE/HOMEPATH",
			envVars: map[string]string{
				"HOMEDRIVE": "C:",
			},
			unsetVars: []string{"HOME", "HOMEPATH", "USERPROFILE", "home"},
			expected: func() string {
				if runtime.GOOS == "windows" {
					return ""
				}
				return ""
			}(),
		},
		{
			name: "windows with only HOMEPATH",
			envVars: map[string]string{
				"HOMEPATH": "\\Users\\user",
			},
			unsetVars: []string{"HOME", "HOMEDRIVE", "USERPROFILE", "home"},
			expected: func() string {
				if runtime.GOOS == "windows" {
					return ""
				}
				return ""
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up environment for this test
			for key, value := range test.envVars {
				os.Setenv(key, value)
			}
			for _, key := range test.unsetVars {
				os.Unsetenv(key)
			}

			result := homeDirUnsafe()

			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestAppConfigDir_XDG_Priority(t *testing.T) {
	// Save original environment
	originalXDG := os.Getenv("XDG_CONFIG_HOME")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_CONFIG_HOME")
		} else {
			os.Setenv("XDG_CONFIG_HOME", originalXDG)
		}
	}()

	// Test XDG_CONFIG_HOME takes priority
	xdgPath := "/custom/config/path"
	os.Setenv("XDG_CONFIG_HOME", xdgPath)

	result := AppConfigDir()
	expected := filepath.Join(xdgPath, "caddy")

	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}

	// Test fallback when XDG_CONFIG_HOME is empty
	os.Unsetenv("XDG_CONFIG_HOME")

	result = AppConfigDir()
	// Should not be the XDG path anymore
	if result == expected {
		t.Error("Should not use XDG path when environment variable is unset")
	}
	// Should contain "caddy" or "Caddy"
	if !strings.Contains(strings.ToLower(result), "caddy") {
		t.Errorf("Result should contain 'caddy': %s", result)
	}
}

func TestAppDataDir_XDG_Priority(t *testing.T) {
	// Save original environment
	originalXDG := os.Getenv("XDG_DATA_HOME")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_DATA_HOME")
		} else {
			os.Setenv("XDG_DATA_HOME", originalXDG)
		}
	}()

	// Test XDG_DATA_HOME takes priority
	xdgPath := "/custom/data/path"
	os.Setenv("XDG_DATA_HOME", xdgPath)

	result := AppDataDir()
	expected := filepath.Join(xdgPath, "caddy")

	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestAppDataDir_PlatformSpecific(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"XDG_DATA_HOME": os.Getenv("XDG_DATA_HOME"),
		"AppData":       os.Getenv("AppData"),
		"HOME":          os.Getenv("HOME"),
		"home":          os.Getenv("home"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Clear XDG to test platform-specific behavior
	os.Unsetenv("XDG_DATA_HOME")

	switch runtime.GOOS {
	case "windows":
		// Test Windows AppData
		os.Setenv("AppData", "C:\\Users\\user\\AppData\\Roaming")
		os.Unsetenv("HOME")
		os.Unsetenv("home")

		result := AppDataDir()
		expected := "C:\\Users\\user\\AppData\\Roaming\\Caddy"
		if result != expected {
			t.Errorf("Windows: Expected '%s', got '%s'", expected, result)
		}

	case "darwin":
		// Test macOS Application Support
		os.Setenv("HOME", "/Users/user")
		os.Unsetenv("AppData")
		os.Unsetenv("home")

		result := AppDataDir()
		expected := "/Users/user/Library/Application Support/Caddy"
		if result != expected {
			t.Errorf("macOS: Expected '%s', got '%s'", expected, result)
		}

	case "plan9":
		// Test Plan9 lib directory
		os.Setenv("home", "/usr/user")
		os.Unsetenv("AppData")
		os.Unsetenv("HOME")

		result := AppDataDir()
		expected := "/usr/user/lib/caddy"
		if result != expected {
			t.Errorf("Plan9: Expected '%s', got '%s'", expected, result)
		}

	default:
		// Test Unix-like systems
		os.Setenv("HOME", "/home/user")
		os.Unsetenv("AppData")
		os.Unsetenv("home")

		result := AppDataDir()
		expected := "/home/user/.local/share/caddy"
		if result != expected {
			t.Errorf("Unix: Expected '%s', got '%s'", expected, result)
		}
	}
}

func TestAppDataDir_Fallback(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"XDG_DATA_HOME": os.Getenv("XDG_DATA_HOME"),
		"AppData":       os.Getenv("AppData"),
		"HOME":          os.Getenv("HOME"),
		"home":          os.Getenv("home"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Unset all relevant environment variables instead of clearing everything
	envVarsToUnset := []string{"XDG_DATA_HOME", "AppData", "HOME", "home"}
	for _, envVar := range envVarsToUnset {
		os.Unsetenv(envVar)
	}

	result := AppDataDir()
	expected := "./caddy"

	if result != expected {
		t.Errorf("Expected fallback '%s', got '%s'", expected, result)
	}
}

func TestConfigAutosavePath_Consistency(t *testing.T) {
	// Test that ConfigAutosavePath uses AppConfigDir
	configDir := AppConfigDir()
	expected := filepath.Join(configDir, "autosave.json")

	if ConfigAutosavePath != expected {
		t.Errorf("ConfigAutosavePath inconsistent with AppConfigDir: expected '%s', got '%s'",
			expected, ConfigAutosavePath)
	}
}

func TestDefaultStorage_Configuration(t *testing.T) {
	// Test that DefaultStorage is properly configured
	if DefaultStorage == nil {
		t.Fatal("DefaultStorage should not be nil")
	}

	// Should use AppDataDir
	expectedPath := AppDataDir()
	if DefaultStorage.Path != expectedPath {
		t.Errorf("DefaultStorage path: expected '%s', got '%s'",
			expectedPath, DefaultStorage.Path)
	}
}

func TestAppDataDir_Android_SpecialCase(t *testing.T) {
	if runtime.GOOS != "android" {
		t.Skip("Android-specific test")
	}

	// Save original environment
	originalEnv := map[string]string{
		"XDG_DATA_HOME": os.Getenv("XDG_DATA_HOME"),
		"HOME":          os.Getenv("HOME"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Clear XDG to test Android-specific behavior
	os.Unsetenv("XDG_DATA_HOME")
	os.Setenv("HOME", "/data/data/com.app")

	result := AppDataDir()
	expected := "/data/data/com.app/caddy"

	if result != expected {
		t.Errorf("Android: Expected '%s', got '%s'", expected, result)
	}
}

func TestHomeDir_Android_SpecialCase(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"HOME":        os.Getenv("HOME"),
		"HOMEDRIVE":   os.Getenv("HOMEDRIVE"),
		"HOMEPATH":    os.Getenv("HOMEPATH"),
		"USERPROFILE": os.Getenv("USERPROFILE"),
		"home":        os.Getenv("home"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Test Android fallback when HOME is not set
	// Also unset Windows and Plan9 specific variables
	os.Unsetenv("HOME")
	os.Unsetenv("HOMEDRIVE")
	os.Unsetenv("HOMEPATH")
	os.Unsetenv("USERPROFILE")
	os.Unsetenv("home")

	result := HomeDir()

	if runtime.GOOS == "android" {
		if result != "/sdcard" {
			t.Errorf("Android with no HOME: Expected '/sdcard', got '%s'", result)
		}
	} else {
		if result != "." {
			t.Errorf("Non-Android with no HOME: Expected '.', got '%s'", result)
		}
	}
}

func TestAppConfigDir_CaseSensitivity(t *testing.T) {
	// Save original environment
	originalXDG := os.Getenv("XDG_CONFIG_HOME")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_CONFIG_HOME")
		} else {
			os.Setenv("XDG_CONFIG_HOME", originalXDG)
		}
	}()

	// Clear XDG to test platform-specific subdirectory naming
	os.Unsetenv("XDG_CONFIG_HOME")

	result := AppConfigDir()

	// Check that the subdirectory name follows platform conventions
	switch runtime.GOOS {
	case "windows", "darwin":
		if !strings.HasSuffix(result, "Caddy") {
			t.Errorf("Expected result to end with 'Caddy' on %s, got '%s'", runtime.GOOS, result)
		}
	default:
		if !strings.HasSuffix(result, "caddy") {
			t.Errorf("Expected result to end with 'caddy' on %s, got '%s'", runtime.GOOS, result)
		}
	}
}

func TestAppDataDir_EmptyEnvironment_Fallback(t *testing.T) {
	// Save all relevant environment variables
	envVars := []string{
		"XDG_DATA_HOME", "AppData", "HOME", "home",
		"HOMEDRIVE", "HOMEPATH", "USERPROFILE",
	}
	originalEnv := make(map[string]string)
	for _, env := range envVars {
		originalEnv[env] = os.Getenv(env)
	}
	defer func() {
		for env, value := range originalEnv {
			if value == "" {
				os.Unsetenv(env)
			} else {
				os.Setenv(env, value)
			}
		}
	}()

	// Clear all environment variables
	for _, env := range envVars {
		os.Unsetenv(env)
	}

	result := AppDataDir()
	expected := "./caddy"

	if result != expected {
		t.Errorf("Expected fallback '%s', got '%s'", expected, result)
	}
}

func TestStorageConverter_Interface(t *testing.T) {
	// Test that the interface is properly defined
	var _ StorageConverter = (*mockStorageConverter)(nil)
}

type mockStorageConverter struct {
	storage *mockStorage
	err     error
}

func (m *mockStorageConverter) CertMagicStorage() (certmagic.Storage, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.storage, nil
}

type mockStorage struct {
	data map[string][]byte
}

func (m *mockStorage) Lock(ctx context.Context, key string) error {
	return nil
}

func (m *mockStorage) Unlock(ctx context.Context, key string) error {
	return nil
}

func (m *mockStorage) Store(ctx context.Context, key string, value []byte) error {
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[key] = value
	return nil
}

func (m *mockStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if m.data == nil {
		return nil, fmt.Errorf("not found")
	}
	value, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("not found")
	}
	return value, nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	if m.data == nil {
		return nil
	}
	delete(m.data, key)
	return nil
}

func (m *mockStorage) Exists(ctx context.Context, key string) bool {
	if m.data == nil {
		return false
	}
	_, exists := m.data[key]
	return exists
}

func (m *mockStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if m.data == nil {
		return nil, nil
	}
	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *mockStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	if !m.Exists(ctx, key) {
		return certmagic.KeyInfo{}, fmt.Errorf("not found")
	}
	value := m.data[key]
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   time.Now(),
		Size:       int64(len(value)),
		IsTerminal: true,
	}, nil
}

func TestStorageConverter_Implementation(t *testing.T) {
	mockStore := &mockStorage{}
	converter := &mockStorageConverter{storage: mockStore}

	storage, err := converter.CertMagicStorage()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if storage != mockStore {
		t.Error("Expected same storage instance")
	}
}

func TestStorageConverter_Error(t *testing.T) {
	expectedErr := fmt.Errorf("storage error")
	converter := &mockStorageConverter{err: expectedErr}

	storage, err := converter.CertMagicStorage()
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
	if storage != nil {
		t.Error("Expected nil storage on error")
	}
}

func TestPathConstruction_Consistency(t *testing.T) {
	// Test that all path functions return valid, absolute paths
	paths := map[string]string{
		"HomeDir":            HomeDir(),
		"AppConfigDir":       AppConfigDir(),
		"AppDataDir":         AppDataDir(),
		"ConfigAutosavePath": ConfigAutosavePath,
	}

	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			if path == "" {
				t.Error("Path should not be empty")
			}

			// Path should not contain null bytes or other invalid characters
			if strings.Contains(path, "\x00") {
				t.Errorf("Path contains null byte: %s", path)
			}

			// HomeDir might return "." which is not absolute
			if name != "HomeDir" && !filepath.IsAbs(path) {
				t.Errorf("Path should be absolute: %s", path)
			}
		})
	}
}

func TestDirectory_Creation_Validation(t *testing.T) {
	// Test directory paths that might be created
	dirs := []string{
		AppConfigDir(),
		AppDataDir(),
		filepath.Dir(ConfigAutosavePath),
	}

	for _, dir := range dirs {
		t.Run(dir, func(t *testing.T) {
			// Verify the directory path is reasonable
			if strings.Contains(dir, "..") {
				t.Errorf("Directory path should not contain '..': %s", dir)
			}

			// On Unix-like systems, check permissions would be appropriate
			if runtime.GOOS != "windows" {
				// Directory should be in user space
				if strings.HasPrefix(dir, "/etc") || strings.HasPrefix(dir, "/var") {
					// These might be valid in some cases, but worth checking
					t.Logf("Warning: Directory in system space: %s", dir)
				}
			}
		})
	}
}

// TestAppConfigDir_ErrorFallback tests the error handling when os.UserConfigDir() fails
// This is difficult to test directly, but we can at least test the fallback behavior
func TestAppConfigDir_ErrorFallback(t *testing.T) {
	// Save original environment
	originalXDG := os.Getenv("XDG_CONFIG_HOME")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_CONFIG_HOME")
		} else {
			os.Setenv("XDG_CONFIG_HOME", originalXDG)
		}
	}()

	// Clear XDG to force use of os.UserConfigDir()
	os.Unsetenv("XDG_CONFIG_HOME")

	// Call AppConfigDir - it should not panic even if there are issues
	result := AppConfigDir()

	// Result should never be empty
	if result == "" {
		t.Error("AppConfigDir should never return empty string")
	}

	// Should contain "caddy" or "Caddy"
	if !strings.Contains(result, "caddy") && !strings.Contains(result, "Caddy") {
		t.Errorf("AppConfigDir should contain 'caddy' or 'Caddy': got '%s'", result)
	}
}

// TestAppDataDir_Darwin_Path tests macOS-specific path construction
func TestAppDataDir_Darwin_Path(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	// Save original environment
	originalXDG := os.Getenv("XDG_DATA_HOME")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_DATA_HOME")
		} else {
			os.Setenv("XDG_DATA_HOME", originalXDG)
		}
	}()

	// Clear XDG to use platform-specific logic
	os.Unsetenv("XDG_DATA_HOME")

	result := AppDataDir()

	// On macOS, should contain "Library/Application Support/Caddy"
	if !strings.Contains(result, "Library") || !strings.Contains(result, "Application Support") {
		t.Errorf("macOS AppDataDir should contain 'Library/Application Support': got '%s'", result)
	}

	if !strings.HasSuffix(result, "Caddy") {
		t.Errorf("macOS AppDataDir should end with 'Caddy': got '%s'", result)
	}
}

// TestAppDataDir_Windows_Path tests Windows-specific path construction
func TestAppDataDir_Windows_Path(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	// Save original environment
	originalXDG := os.Getenv("XDG_DATA_HOME")
	originalAppData := os.Getenv("AppData")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_DATA_HOME")
		} else {
			os.Setenv("XDG_DATA_HOME", originalXDG)
		}
		if originalAppData == "" {
			os.Unsetenv("AppData")
		} else {
			os.Setenv("AppData", originalAppData)
		}
	}()

	// Clear XDG to use platform-specific logic
	os.Unsetenv("XDG_DATA_HOME")

	// Set AppData
	os.Setenv("AppData", "C:\\Users\\TestUser\\AppData\\Roaming")

	result := AppDataDir()

	// On Windows, should use AppData and end with "Caddy"
	if !strings.Contains(result, "AppData") {
		t.Errorf("Windows AppDataDir should contain 'AppData': got '%s'", result)
	}

	if !strings.HasSuffix(result, "Caddy") {
		t.Errorf("Windows AppDataDir should end with 'Caddy': got '%s'", result)
	}
}

// TODO: Should this be kept? We cannot test plan9. We don't have plan9 CI.
// TestAppDataDir_Plan9_Path tests Plan9-specific path construction
// func TestAppDataDir_Plan9_Path(t *testing.T) {
// 	if runtime.GOOS != "plan9" {
// 		t.Skip("Plan9-specific test")
// 	}

// 	// Save original environment
// 	originalXDG := os.Getenv("XDG_DATA_HOME")
// 	originalHome := os.Getenv("home")
// 	defer func() {
// 		if originalXDG == "" {
// 			os.Unsetenv("XDG_DATA_HOME")
// 		} else {
// 			os.Setenv("XDG_DATA_HOME", originalXDG)
// 		}
// 		if originalHome == "" {
// 			os.Unsetenv("home")
// 		} else {
// 			os.Setenv("home", originalHome)
// 		}
// 	}()

// 	// Clear XDG to use platform-specific logic
// 	os.Unsetenv("XDG_DATA_HOME")
// 	os.Setenv("home", "/usr/testuser")

// 	result := AppDataDir()

// 	// On Plan9, should contain "lib/caddy"
// 	expectedPath := filepath.Join("/usr/testuser", "lib", "caddy")
// 	if result != expectedPath {
// 		t.Errorf("Plan9 AppDataDir: expected '%s', got '%s'", expectedPath, result)
// 	}
// }

// TestAppDataDir_Linux_Path tests Linux/Unix-specific path construction
func TestAppDataDir_Linux_Path(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	// Save original environment
	originalXDG := os.Getenv("XDG_DATA_HOME")
	originalHOME := os.Getenv("HOME")
	defer func() {
		if originalXDG == "" {
			os.Unsetenv("XDG_DATA_HOME")
		} else {
			os.Setenv("XDG_DATA_HOME", originalXDG)
		}
		if originalHOME == "" {
			os.Unsetenv("HOME")
		} else {
			os.Setenv("HOME", originalHOME)
		}
	}()

	// Clear XDG to use platform-specific logic
	os.Unsetenv("XDG_DATA_HOME")
	os.Setenv("HOME", "/home/testuser")

	result := AppDataDir()

	// On Linux, should contain ".local/share/caddy"
	expectedPath := filepath.Join("/home/testuser", ".local", "share", "caddy")
	if result != expectedPath {
		t.Errorf("Linux AppDataDir: expected '%s', got '%s'", expectedPath, result)
	}
}

// TODO: Should this be kept? We cannot test plan9. We don't have plan9 CI.
// TestHomeDirUnsafe_Plan9 tests Plan9-specific home directory detection
// func TestHomeDirUnsafe_Plan9(t *testing.T) {
// 	if runtime.GOOS != "plan9" {
// 		t.Skip("Plan9-specific test")
// 	}

// 	// Save original environment
// 	originalHome := os.Getenv("HOME")
// 	originalHomeLC := os.Getenv("home")
// 	defer func() {
// 		if originalHome == "" {
// 			os.Unsetenv("HOME")
// 		} else {
// 			os.Setenv("HOME", originalHome)
// 		}
// 		if originalHomeLC == "" {
// 			os.Unsetenv("home")
// 		} else {
// 			os.Setenv("home", originalHomeLC)
// 		}
// 	}()

// 	// Test with Plan9's lowercase "home" variable
// 	os.Unsetenv("HOME")
// 	os.Setenv("home", "/usr/plan9user")

// 	result := homeDirUnsafe()

// 	if result != "/usr/plan9user" {
// 		t.Errorf("Plan9 homeDirUnsafe: expected '/usr/plan9user', got '%s'", result)
// 	}
// }

// TestHomeDirUnsafe_Windows tests Windows-specific home directory detection
func TestHomeDirUnsafe_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	// Save original environment
	originalEnv := map[string]string{
		"HOME":        os.Getenv("HOME"),
		"HOMEDRIVE":   os.Getenv("HOMEDRIVE"),
		"HOMEPATH":    os.Getenv("HOMEPATH"),
		"USERPROFILE": os.Getenv("USERPROFILE"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Test HOMEDRIVE + HOMEPATH combination
	os.Unsetenv("HOME")
	os.Setenv("HOMEDRIVE", "C:")
	os.Setenv("HOMEPATH", "\\Users\\TestUser")
	os.Unsetenv("USERPROFILE")

	result := homeDirUnsafe()
	expected := "C:\\Users\\TestUser"

	if result != expected {
		t.Errorf("Windows homeDirUnsafe with HOMEDRIVE+HOMEPATH: expected '%s', got '%s'", expected, result)
	}

	// Test USERPROFILE fallback when HOMEDRIVE or HOMEPATH is missing
	os.Unsetenv("HOME")
	os.Unsetenv("HOMEDRIVE")
	os.Setenv("HOMEPATH", "\\Users\\TestUser")
	os.Setenv("USERPROFILE", "C:\\Users\\TestUser")

	result = homeDirUnsafe()
	expected = "C:\\Users\\TestUser"

	if result != expected {
		t.Errorf("Windows homeDirUnsafe with USERPROFILE: expected '%s', got '%s'", expected, result)
	}

	// Test when only HOMEDRIVE is set (should use USERPROFILE)
	os.Unsetenv("HOME")
	os.Setenv("HOMEDRIVE", "C:")
	os.Unsetenv("HOMEPATH")
	os.Setenv("USERPROFILE", "C:\\Users\\TestUser")

	result = homeDirUnsafe()
	expected = "C:\\Users\\TestUser"

	if result != expected {
		t.Errorf("Windows homeDirUnsafe with only HOMEDRIVE: expected '%s', got '%s'", expected, result)
	}
}

// TestConfigAutosavePath_NotEmpty tests that ConfigAutosavePath is always set
func TestConfigAutosavePath_NotEmpty(t *testing.T) {
	if ConfigAutosavePath == "" {
		t.Error("ConfigAutosavePath should not be empty")
	}

	if !strings.HasSuffix(ConfigAutosavePath, "autosave.json") {
		t.Errorf("ConfigAutosavePath should end with 'autosave.json': got '%s'", ConfigAutosavePath)
	}

	// Should be an absolute path
	if !filepath.IsAbs(ConfigAutosavePath) {
		t.Errorf("ConfigAutosavePath should be absolute: got '%s'", ConfigAutosavePath)
	}
}

// TestDefaultStorage_NotNil tests that DefaultStorage is initialized
func TestDefaultStorage_NotNil(t *testing.T) {
	if DefaultStorage == nil {
		t.Fatal("DefaultStorage should not be nil")
	}

	if DefaultStorage.Path == "" {
		t.Error("DefaultStorage.Path should not be empty")
	}

	// Path should be absolute
	if !filepath.IsAbs(DefaultStorage.Path) {
		t.Errorf("DefaultStorage.Path should be absolute: got '%s'", DefaultStorage.Path)
	}
}

// TestAppDataDir_NoHome_Fallback tests fallback when no home directory can be determined
func TestAppDataDir_NoHome_Fallback(t *testing.T) {
	// Skip on platforms where we can't easily clear all home-related variables
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "plan9" {
		t.Skip("Skipping on platforms where clearing home is complex")
	}

	// Save original environment
	originalEnv := map[string]string{
		"XDG_DATA_HOME": os.Getenv("XDG_DATA_HOME"),
		"HOME":          os.Getenv("HOME"),
		"AppData":       os.Getenv("AppData"),
		"home":          os.Getenv("home"),
	}
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Clear all relevant environment variables
	os.Unsetenv("XDG_DATA_HOME")
	os.Unsetenv("HOME")
	os.Unsetenv("AppData")
	os.Unsetenv("home")

	result := AppDataDir()

	// Should fall back to "./caddy"
	if result != "./caddy" {
		t.Errorf("AppDataDir with no home should return './caddy', got '%s'", result)
	}
}

func BenchmarkHomeDir(b *testing.B) {
	for i := 0; i < b.N; i++ {
		HomeDir()
	}
}

func BenchmarkAppConfigDir(b *testing.B) {
	for i := 0; i < b.N; i++ {
		AppConfigDir()
	}
}

func BenchmarkAppDataDir(b *testing.B) {
	for i := 0; i < b.N; i++ {
		AppDataDir()
	}
}
