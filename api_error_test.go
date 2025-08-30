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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestAPIError_Error_WithErr(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	apiErr := APIError{
		HTTPStatus: http.StatusBadRequest,
		Err:        underlyingErr,
		Message:    "API error message",
	}
	
	result := apiErr.Error()
	expected := "underlying error"
	
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestAPIError_Error_WithoutErr(t *testing.T) {
	apiErr := APIError{
		HTTPStatus: http.StatusBadRequest,
		Err:        nil,
		Message:    "API error message",
	}
	
	result := apiErr.Error()
	expected := "API error message"
	
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestAPIError_Error_BothNil(t *testing.T) {
	apiErr := APIError{
		HTTPStatus: http.StatusBadRequest,
		Err:        nil,
		Message:    "",
	}
	
	result := apiErr.Error()
	expected := ""
	
	if result != expected {
		t.Errorf("Expected empty string, got '%s'", result)
	}
}

func TestAPIError_JSON_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		apiErr APIError
	}{
		{
			name: "with message only",
			apiErr: APIError{
				HTTPStatus: http.StatusBadRequest,
				Message:    "validation failed",
			},
		},
		{
			name: "with underlying error only",
			apiErr: APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        errors.New("internal error"),
			},
		},
		{
			name: "with both message and error",
			apiErr: APIError{
				HTTPStatus: http.StatusConflict,
				Err:        errors.New("underlying"),
				Message:    "conflict detected",
			},
		},
		{
			name: "minimal error",
			apiErr: APIError{
				HTTPStatus: http.StatusNotFound,
			},
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(test.apiErr)
			if err != nil {
				t.Fatalf("Failed to marshal APIError: %v", err)
			}
			
			// Unmarshal back
			var unmarshaled APIError
			err = json.Unmarshal(jsonData, &unmarshaled)
			if err != nil {
				t.Fatalf("Failed to unmarshal APIError: %v", err)
			}
			
			// Only Message field should survive JSON round-trip
			// HTTPStatus and Err are marked with json:"-"
			if unmarshaled.Message != test.apiErr.Message {
				t.Errorf("Message mismatch: expected '%s', got '%s'", 
					test.apiErr.Message, unmarshaled.Message)
			}
			
			// HTTPStatus and Err should be zero values after unmarshal
			if unmarshaled.HTTPStatus != 0 {
				t.Errorf("HTTPStatus should be 0 after unmarshal, got %d", unmarshaled.HTTPStatus)
			}
			if unmarshaled.Err != nil {
				t.Errorf("Err should be nil after unmarshal, got %v", unmarshaled.Err)
			}
		})
	}
}

func TestAPIError_HTTPStatus_Values(t *testing.T) {
	// Test common HTTP status codes
	statusCodes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusConflict,
		http.StatusPreconditionFailed,
		http.StatusInternalServerError,
		http.StatusNotImplemented,
		http.StatusServiceUnavailable,
	}
	
	for _, status := range statusCodes {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			apiErr := APIError{
				HTTPStatus: status,
				Message:    http.StatusText(status),
			}
			
			if apiErr.HTTPStatus != status {
				t.Errorf("Expected status %d, got %d", status, apiErr.HTTPStatus)
			}
			
			// Test that error message is reasonable
			if apiErr.Message == "" && status >= 400 {
				t.Errorf("Status %d should have a message", status)
			}
		})
	}
}

func TestAPIError_ErrorInterface_Compliance(t *testing.T) {
	// Verify APIError properly implements error interface
	var err error = APIError{
		HTTPStatus: http.StatusBadRequest,
		Message:    "test error",
	}
	
	errorMsg := err.Error()
	if errorMsg != "test error" {
		t.Errorf("Expected 'test error', got '%s'", errorMsg)
	}
	
	// Test with underlying error
	underlyingErr := errors.New("underlying")
	err2 := APIError{
		HTTPStatus: http.StatusInternalServerError,
		Err:        underlyingErr,
		Message:    "wrapper",
	}
	
	if err2.Error() != "underlying" {
		t.Errorf("Expected 'underlying', got '%s'", err2.Error())
	}
}

func TestAPIError_JSON_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{
			name:    "empty message",
			message: "",
		},
		{
			name:    "unicode message",
			message: "Error: 🚨 Something went wrong! 你好",
		},
		{
			name:    "json characters in message",
			message: `Error with "quotes" and {brackets}`,
		},
		{
			name:    "newlines in message",
			message: "Line 1\nLine 2\r\nLine 3",
		},
		{
			name:    "very long message",
			message: string(make([]byte, 10000)), // 10KB message
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiErr := APIError{
				HTTPStatus: http.StatusBadRequest,
				Message:    test.message,
			}
			
			// Should be JSON serializable
			jsonData, err := json.Marshal(apiErr)
			if err != nil {
				t.Fatalf("Failed to marshal APIError: %v", err)
			}
			
			// Should be deserializable
			var unmarshaled APIError
			err = json.Unmarshal(jsonData, &unmarshaled)
			if err != nil {
				t.Fatalf("Failed to unmarshal APIError: %v", err)
			}
			
			if unmarshaled.Message != test.message {
				t.Errorf("Message corrupted during JSON round-trip")
			}
		})
	}
}

func TestAPIError_Chaining(t *testing.T) {
	// Test error chaining scenarios
	rootErr := errors.New("root cause")
	wrappedErr := fmt.Errorf("wrapped: %w", rootErr)
	
	apiErr := APIError{
		HTTPStatus: http.StatusInternalServerError,
		Err:        wrappedErr,
		Message:    "API wrapper",
	}
	
	// Error() should return the underlying error message
	if apiErr.Error() != wrappedErr.Error() {
		t.Errorf("Expected underlying error message, got '%s'", apiErr.Error())
	}
	
	// Should be able to unwrap
	if !errors.Is(apiErr.Err, rootErr) {
		t.Error("Should be able to unwrap to root cause")
	}
}

func TestAPIError_StatusCode_Boundaries(t *testing.T) {
	// Test edge cases for HTTP status codes
	tests := []struct {
		name   string
		status int
		valid  bool
	}{
		{
			name:   "negative status",
			status: -1,
			valid:  false,
		},
		{
			name:   "zero status",
			status: 0,
			valid:  false,
		},
		{
			name:   "valid 1xx",
			status: http.StatusContinue,
			valid:  true,
		},
		{
			name:   "valid 2xx",
			status: http.StatusOK,
			valid:  true,
		},
		{
			name:   "valid 4xx",
			status: http.StatusBadRequest,
			valid:  true,
		},
		{
			name:   "valid 5xx", 
			status: http.StatusInternalServerError,
			valid:  true,
		},
		{
			name:   "too large status",
			status: 9999,
			valid:  false,
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := APIError{
				HTTPStatus: test.status,
				Message:    "test",
			}
			
			// The struct allows any int value, but we can test
			// if it's a valid HTTP status
			statusText := http.StatusText(test.status)
			isValidStatus := statusText != ""
			
			if isValidStatus != test.valid {
				t.Errorf("Status %d validity: expected %v, got %v", 
					test.status, test.valid, isValidStatus)
			}
			
			// Verify the struct holds the status
			if err.HTTPStatus != test.status {
				t.Errorf("Status not preserved: expected %d, got %d", test.status, err.HTTPStatus)
			}
		})
	}
}

func BenchmarkAPIError_Error(b *testing.B) {
	apiErr := APIError{
		HTTPStatus: http.StatusBadRequest,
		Err:        errors.New("benchmark error"),
		Message:    "benchmark message",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		apiErr.Error()
	}
}

func BenchmarkAPIError_JSON_Marshal(b *testing.B) {
	apiErr := APIError{
		HTTPStatus: http.StatusBadRequest,
		Err:        errors.New("benchmark error"),
		Message:    "benchmark message",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(apiErr)
	}
}

func BenchmarkAPIError_JSON_Unmarshal(b *testing.B) {
	jsonData := []byte(`{"error": "benchmark message"}`)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result APIError
		_ = json.Unmarshal(jsonData, &result)
	}
}
