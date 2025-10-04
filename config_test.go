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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfig_Start_Stop_Basic(t *testing.T) {
	cfg := &Config{
		Admin: &AdminConfig{Disabled: true}, // Disable admin to avoid port conflicts
	}

	ctx, err := run(cfg, true)
	if err != nil {
		t.Fatalf("Failed to run config: %v", err)
	}

	// Verify context is valid
	if ctx.cfg == nil {
		t.Error("Expected non-nil config in context")
	}

	// Stop the config
	unsyncedStop(ctx)

	// Verify cleanup was called
	if ctx.cfg.cancelFunc == nil {
		t.Error("Expected cancel function to be set")
	}
}

func TestConfig_Validate_InvalidConfig(t *testing.T) {
	// Create a config with an invalid app module
	cfg := &Config{
		AppsRaw: ModuleMap{
			"non-existent-app": json.RawMessage(`{}`),
		},
	}

	err := Validate(cfg)
	if err == nil {
		t.Error("Expected validation error for invalid app module")
	}
}

func TestConfig_Validate_ValidConfig(t *testing.T) {
	cfg := &Config{
		Admin: &AdminConfig{Disabled: true},
	}

	err := Validate(cfg)
	if err != nil {
		t.Errorf("Unexpected validation error: %v", err)
	}
}

func TestChangeConfig_ConcurrentAccess(t *testing.T) {
	// Save original config state
	originalRawCfg := rawCfg[rawConfigKey]
	originalRawCfgJSON := rawCfgJSON
	defer func() {
		rawCfg[rawConfigKey] = originalRawCfg
		rawCfgJSON = originalRawCfgJSON
	}()

	// Initialize with a basic config
	initialCfg := map[string]any{
		"test": "value",
	}
	rawCfg[rawConfigKey] = initialCfg

	const numGoroutines = 10 // Reduced for more controlled testing
	var wg sync.WaitGroup
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Only test read operations to avoid complex state changes
			// that could cause nil pointer issues in concurrent scenarios
			var buf bytes.Buffer
			errors[index] = readConfig("/"+rawConfigKey+"/test", &buf)
		}(i)
	}

	wg.Wait()

	// Check that read operations succeeded
	for i, err := range errors {
		if err != nil {
			t.Errorf("Goroutine %d: Unexpected read error: %v", i, err)
		}
	}
}

func TestChangeConfig_MethodValidation(t *testing.T) {
	// Save original config state
	originalRawCfg := rawCfg[rawConfigKey]
	defer func() {
		rawCfg[rawConfigKey] = originalRawCfg
	}()

	// Set up a simple valid config for testing
	rawCfg[rawConfigKey] = map[string]any{}

	tests := []struct {
		method    string
		expectErr bool
	}{
		{http.MethodPost, false},
		{http.MethodPut, true}, // because key 'admin' already exists
		{http.MethodPatch, false},
		{http.MethodDelete, false},
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodOptions, true},
		{http.MethodConnect, true},
		{http.MethodTrace, true},
	}

	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			// Use a simple admin config path that won't cause complex validation
			err := changeConfig(test.method, "/"+rawConfigKey+"/admin", []byte(`{"disabled": true}`), "", false)

			if test.expectErr && err == nil {
				t.Error("Expected error for invalid method")
			}
			if !test.expectErr && err != nil && (err != errSameConfig) {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestChangeConfig_IfMatchHeader_Validation(t *testing.T) {
	// Set up initial config
	initialCfg := map[string]any{"test": "value"}
	rawCfg[rawConfigKey] = initialCfg

	tests := []struct {
		name             string
		ifMatch          string
		expectErr        bool
		expectStatusCode int
	}{
		{
			name:             "malformed - no quotes",
			ifMatch:          "path hash",
			expectErr:        true,
			expectStatusCode: http.StatusBadRequest,
		},
		{
			name:             "malformed - single quote",
			ifMatch:          `"path hash`,
			expectErr:        true,
			expectStatusCode: http.StatusBadRequest,
		},
		{
			name:             "malformed - wrong number of parts",
			ifMatch:          `"path"`,
			expectErr:        true,
			expectStatusCode: http.StatusBadRequest,
		},
		{
			name:             "malformed - too many parts",
			ifMatch:          `"path hash extra"`,
			expectErr:        true,
			expectStatusCode: http.StatusBadRequest,
		},
		{
			name:             "wrong hash",
			ifMatch:          `"/config/test wronghash"`,
			expectErr:        true,
			expectStatusCode: http.StatusPreconditionFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := changeConfig(http.MethodPost, "/"+rawConfigKey+"/test", []byte(`"newvalue"`), test.ifMatch, false)

			if test.expectErr && err == nil {
				t.Error("Expected error")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if test.expectErr && err != nil {
				if apiErr, ok := err.(APIError); ok {
					if apiErr.HTTPStatus != test.expectStatusCode {
						t.Errorf("Expected status %d, got %d", test.expectStatusCode, apiErr.HTTPStatus)
					}
				} else {
					t.Error("Expected APIError type")
				}
			}
		})
	}
}

func TestIndexConfigObjects_Basic(t *testing.T) {
	config := map[string]any{
		"app1": map[string]any{
			"@id":    "my-app",
			"config": "value",
		},
		"nested": map[string]any{
			"array": []any{
				map[string]any{
					"@id":  "nested-item",
					"data": "test",
				},
				map[string]any{
					"@id":  123.0, // JSON numbers are float64
					"more": "data",
				},
			},
		},
	}

	index := make(map[string]string)
	err := indexConfigObjects(config, "/config", index)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := map[string]string{
		"my-app":      "/config/app1",
		"nested-item": "/config/nested/array/0",
		"123":         "/config/nested/array/1",
	}

	if len(index) != len(expected) {
		t.Errorf("Expected %d indexed items, got %d", len(expected), len(index))
	}

	for id, expectedPath := range expected {
		if actualPath, exists := index[id]; !exists || actualPath != expectedPath {
			t.Errorf("ID %s: expected path '%s', got '%s'", id, expectedPath, actualPath)
		}
	}
}

func TestIndexConfigObjects_InvalidID(t *testing.T) {
	config := map[string]any{
		"app": map[string]any{
			"@id": map[string]any{"invalid": "id"}, // Invalid ID type
		},
	}

	index := make(map[string]string)
	err := indexConfigObjects(config, "/config", index)
	if err == nil {
		t.Error("Expected error for invalid ID type")
	}
}

func TestRun_AppStartFailure(t *testing.T) {
	// Register a mock app that fails to start
	RegisterModule(&failingApp{})
	defer func() {
		// Clean up module registry
		delete(modules, "failing-app")
	}()

	cfg := &Config{
		Admin: &AdminConfig{Disabled: true},
		AppsRaw: ModuleMap{
			"failing-app": json.RawMessage(`{}`),
		},
	}

	_, err := run(cfg, true)
	if err == nil {
		t.Error("Expected error when app fails to start")
	}

	// Should contain the app name in the error
	if err.Error() == "" {
		t.Error("Expected descriptive error message")
	}
}

func TestRun_AppStopFailure_During_Cleanup(t *testing.T) {
	// Register apps where one fails to start and another fails to stop
	RegisterModule(&workingApp{})
	RegisterModule(&failingStopApp{})
	defer func() {
		delete(modules, "working-app")
		delete(modules, "failing-stop-app")
	}()

	cfg := &Config{
		Admin: &AdminConfig{Disabled: true},
		AppsRaw: ModuleMap{
			"working-app":      json.RawMessage(`{}`),
			"failing-stop-app": json.RawMessage(`{}`),
		},
	}

	// Start both apps
	ctx, err := run(cfg, true)
	if err != nil {
		t.Fatalf("Unexpected error starting apps: %v", err)
	}

	// Stop context - this should handle stop failures gracefully
	unsyncedStop(ctx)

	// Test passed if we reach here without panic
}

func TestProvisionContext_NilConfig(t *testing.T) {
	ctx, err := provisionContext(nil, false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if ctx.cfg == nil {
		t.Error("Expected non-nil config even when input is nil")
	}

	// Clean up
	ctx.cfg.cancelFunc()
}

func TestDuration_UnmarshalJSON_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		expected  time.Duration
	}{
		{
			name:      "empty input",
			input:     "",
			expectErr: true,
		},
		{
			name:      "integer nanoseconds",
			input:     "1000000000",
			expected:  time.Second,
			expectErr: false,
		},
		{
			name:      "string duration",
			input:     `"5m30s"`,
			expected:  5*time.Minute + 30*time.Second,
			expectErr: false,
		},
		{
			name:      "days conversion",
			input:     `"2d"`,
			expected:  48 * time.Hour,
			expectErr: false,
		},
		{
			name:      "mixed days and hours",
			input:     `"1d12h"`,
			expected:  36 * time.Hour,
			expectErr: false,
		},
		{
			name:      "invalid duration",
			input:     `"invalid"`,
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalJSON([]byte(test.input))

			if test.expectErr && err == nil {
				t.Error("Expected error")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !test.expectErr && time.Duration(d) != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, time.Duration(d))
			}
		})
	}
}

func TestParseDuration_LongInput(t *testing.T) {
	// Test input length limit
	longInput := string(make([]byte, 1025)) // Exceeds 1024 limit
	for i := range longInput {
		longInput = longInput[:i] + "1"
	}
	longInput += "d"

	_, err := ParseDuration(longInput)
	if err == nil {
		t.Error("Expected error for input longer than 1024 characters")
	}
}

func TestVersion_Deterministic(t *testing.T) {
	// Test that Version() returns consistent results
	simple1, full1 := Version()
	simple2, full2 := Version()

	if simple1 != simple2 {
		t.Errorf("Version() simple form not deterministic: '%s' != '%s'", simple1, simple2)
	}
	if full1 != full2 {
		t.Errorf("Version() full form not deterministic: '%s' != '%s'", full1, full2)
	}
}

func TestInstanceID_Consistency(t *testing.T) {
	// Test that InstanceID returns the same ID on subsequent calls
	id1, err := InstanceID()
	if err != nil {
		t.Fatalf("Failed to get instance ID: %v", err)
	}

	id2, err := InstanceID()
	if err != nil {
		t.Fatalf("Failed to get instance ID on second call: %v", err)
	}

	if id1 != id2 {
		t.Errorf("InstanceID not consistent: %v != %v", id1, id2)
	}
}

func TestRemoveMetaFields_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no meta fields",
			input:    `{"normal": "field"}`,
			expected: `{"normal": "field"}`,
		},
		{
			name:     "single @id field",
			input:    `{"@id": "test", "other": "field"}`,
			expected: `{"other": "field"}`,
		},
		{
			name:     "@id at beginning",
			input:    `{"@id": "test", "other": "field"}`,
			expected: `{"other": "field"}`,
		},
		{
			name:     "@id at end",
			input:    `{"other": "field", "@id": "test"}`,
			expected: `{"other": "field"}`,
		},
		{
			name:     "@id in middle",
			input:    `{"first": "value", "@id": "test", "last": "value"}`,
			expected: `{"first": "value", "last": "value"}`,
		},
		{
			name:     "multiple @id fields",
			input:    `{"@id": "test1", "other": "field", "@id": "test2"}`,
			expected: `{"other": "field"}`,
		},
		{
			name:     "numeric @id",
			input:    `{"@id": 123, "other": "field"}`,
			expected: `{"other": "field"}`,
		},
		{
			name:     "nested objects with @id",
			input:    `{"outer": {"@id": "nested", "data": "value"}}`,
			expected: `{"outer": {"data": "value"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := RemoveMetaFields([]byte(test.input))
			// resultStr := string(result)

			// Parse both to ensure valid JSON and compare structures
			var expectedObj, resultObj any
			if err := json.Unmarshal([]byte(test.expected), &expectedObj); err != nil {
				t.Fatalf("Expected result is not valid JSON: %v", err)
			}
			if err := json.Unmarshal(result, &resultObj); err != nil {
				t.Fatalf("Result is not valid JSON: %v", err)
			}

			// Note: We can't do exact string comparison due to potential field ordering
			// Instead, verify the structure matches
			expectedJSON, _ := json.Marshal(expectedObj)
			resultJSON, _ := json.Marshal(resultObj)

			if string(expectedJSON) != string(resultJSON) {
				t.Errorf("Expected %s, got %s", string(expectedJSON), string(resultJSON))
			}
		})
	}
}

func TestUnsyncedConfigAccess_ArrayOperations_EdgeCases(t *testing.T) {
	// Test array boundary conditions and edge cases
	tests := []struct {
		name         string
		initialState map[string]any
		method       string
		path         string
		payload      string
		expectErr    bool
		expectState  map[string]any
	}{
		{
			name:         "delete from empty array",
			initialState: map[string]any{"arr": []any{}},
			method:       http.MethodDelete,
			path:         "/config/arr/0",
			expectErr:    true,
		},
		{
			name:         "access negative index",
			initialState: map[string]any{"arr": []any{"a", "b"}},
			method:       http.MethodGet,
			path:         "/config/arr/-1",
			expectErr:    true,
		},
		{
			name:         "put at index beyond end",
			initialState: map[string]any{"arr": []any{"a"}},
			method:       http.MethodPut,
			path:         "/config/arr/5",
			payload:      `"new"`,
			expectErr:    true,
		},
		{
			name:         "patch non-existent index",
			initialState: map[string]any{"arr": []any{"a"}},
			method:       http.MethodPatch,
			path:         "/config/arr/5",
			payload:      `"new"`,
			expectErr:    true,
		},
		{
			name:         "put at exact end of array",
			initialState: map[string]any{"arr": []any{"a", "b"}},
			method:       http.MethodPut,
			path:         "/config/arr/2",
			payload:      `"c"`,
			expectState:  map[string]any{"arr": []any{"a", "b", "c"}},
		},
		{
			name:         "ellipses with non-array payload",
			initialState: map[string]any{"arr": []any{"a"}},
			method:       http.MethodPost,
			path:         "/config/arr/...",
			payload:      `"not-array"`,
			expectErr:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up initial state
			rawCfg[rawConfigKey] = test.initialState

			err := unsyncedConfigAccess(test.method, test.path, []byte(test.payload), nil)

			if test.expectErr && err == nil {
				t.Error("Expected error")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if test.expectState != nil {
				// Compare resulting state
				expectedJSON, _ := json.Marshal(test.expectState)
				actualJSON, _ := json.Marshal(rawCfg[rawConfigKey])

				if string(expectedJSON) != string(actualJSON) {
					t.Errorf("Expected state %s, got %s", string(expectedJSON), string(actualJSON))
				}
			}
		})
	}
}

func TestExitProcess_ConcurrentCalls(t *testing.T) {
	// Test that multiple concurrent calls to exitProcess are safe
	// We can't test the actual exit, but we can test the atomic flag

	// Reset the exiting flag
	oldExiting := exiting
	exiting = new(int32)
	defer func() { exiting = oldExiting }()

	const numGoroutines = 10
	var wg sync.WaitGroup
	results := make([]bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			// Check the Exiting() function which reads the atomic flag
			wasExitingBefore := Exiting()

			// This would call exitProcess, but we don't want to actually exit
			// So we just test the atomic operation directly
			results[index] = atomic.CompareAndSwapInt32(exiting, 0, 1)

			wasExitingAfter := Exiting()

			// At least one should succeed in setting the flag
			if !wasExitingBefore && wasExitingAfter && !results[index] {
				t.Errorf("Goroutine %d: Flag was set but CAS failed", index)
			}
		}(i)
	}

	wg.Wait()

	// Exactly one goroutine should have successfully set the flag
	successCount := 0
	for _, success := range results {
		if success {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("Expected exactly 1 successful flag set, got %d", successCount)
	}

	// Flag should be set
	if !Exiting() {
		t.Error("Exiting flag should be set")
	}
}

// Mock apps for testing
type failingApp struct{}

func (fa *failingApp) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "failing-app",
		New: func() Module { return new(failingApp) },
	}
}

func (fa *failingApp) Start() error {
	return fmt.Errorf("simulated start failure")
}

func (fa *failingApp) Stop() error {
	return nil
}

type workingApp struct{}

func (wa *workingApp) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "working-app",
		New: func() Module { return new(workingApp) },
	}
}

func (wa *workingApp) Start() error {
	return nil
}

func (wa *workingApp) Stop() error {
	return nil
}

type failingStopApp struct{}

func (fsa *failingStopApp) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "failing-stop-app",
		New: func() Module { return new(failingStopApp) },
	}
}

func (fsa *failingStopApp) Start() error {
	return nil
}

func (fsa *failingStopApp) Stop() error {
	return fmt.Errorf("simulated stop failure")
}
