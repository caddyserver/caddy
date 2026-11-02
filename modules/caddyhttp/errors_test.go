package caddyhttp

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestHandlerErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      HandlerError
		contains []string
	}{
		{
			name: "full error",
			err: HandlerError{
				ID:         "abc123",
				StatusCode: 404,
				Err:        fmt.Errorf("not found"),
				Trace:      "pkg.Func (file.go:10)",
			},
			contains: []string{"abc123", "404", "not found", "pkg.Func"},
		},
		{
			name:     "empty error",
			err:      HandlerError{},
			contains: []string{},
		},
		{
			name: "error with only status code",
			err: HandlerError{
				StatusCode: 500,
			},
			contains: []string{"500"},
		},
		{
			name: "error with only message",
			err: HandlerError{
				Err: fmt.Errorf("something broke"),
			},
			contains: []string{"something broke"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			for _, needle := range tt.contains {
				if !strings.Contains(result, needle) {
					t.Errorf("Error() = %q, should contain %q", result, needle)
				}
			}
		})
	}
}

func TestHandlerErrorUnwrap(t *testing.T) {
	originalErr := fmt.Errorf("original error")
	he := HandlerError{Err: originalErr}

	unwrapped := he.Unwrap()
	if unwrapped != originalErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, originalErr)
	}
}

func TestError(t *testing.T) {
	t.Run("creates error with ID and trace", func(t *testing.T) {
		err := fmt.Errorf("test error")
		he := Error(500, err)

		if he.StatusCode != 500 {
			t.Errorf("StatusCode = %d, want 500", he.StatusCode)
		}
		if he.ID == "" {
			t.Error("ID should not be empty")
		}
		if len(he.ID) != 9 {
			t.Errorf("ID length = %d, want 9", len(he.ID))
		}
		if he.Trace == "" {
			t.Error("Trace should not be empty")
		}
		if he.Err != err {
			t.Error("Err should be the original error")
		}
	})

	t.Run("unwraps existing HandlerError", func(t *testing.T) {
		inner := HandlerError{
			ID:         "existing_id",
			StatusCode: 404,
			Err:        fmt.Errorf("not found"),
			Trace:      "existing trace",
		}

		he := Error(500, inner)

		// Should keep existing ID
		if he.ID != "existing_id" {
			t.Errorf("ID = %q, want 'existing_id'", he.ID)
		}
		// Should keep existing StatusCode
		if he.StatusCode != 404 {
			t.Errorf("StatusCode = %d, want 404 (existing)", he.StatusCode)
		}
		// Should keep existing Trace
		if he.Trace != "existing trace" {
			t.Errorf("Trace = %q, want 'existing trace'", he.Trace)
		}
	})

	t.Run("fills missing fields in existing HandlerError", func(t *testing.T) {
		inner := HandlerError{
			Err: fmt.Errorf("inner error"),
			// ID, StatusCode, and Trace are all empty
		}

		he := Error(503, inner)

		if he.ID == "" {
			t.Error("should fill missing ID")
		}
		if he.StatusCode != 503 {
			t.Errorf("should fill missing StatusCode with %d, got %d", 503, he.StatusCode)
		}
		if he.Trace == "" {
			t.Error("should fill missing Trace")
		}
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		ids := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			he := Error(500, fmt.Errorf("error %d", i))
			if _, exists := ids[he.ID]; exists {
				t.Errorf("duplicate ID generated: %s", he.ID)
			}
			ids[he.ID] = struct{}{}
		}
	})
}

func TestErrorAsHandlerError(t *testing.T) {
	he := Error(404, fmt.Errorf("not found"))
	var target HandlerError
	if !errors.As(he, &target) {
		t.Error("Error() result should be assertable as HandlerError via errors.As")
	}
}

func TestHandlerErrorWithWrappedError(t *testing.T) {
	// Test that errors.As can unwrap a wrapped HandlerError
	inner := HandlerError{
		ID:         "inner",
		StatusCode: 404,
		Err:        fmt.Errorf("inner error"),
	}
	wrapped := fmt.Errorf("wrapped: %w", inner)

	he := Error(500, wrapped)
	// Since wrapped contains a HandlerError, it should be unwrapped
	if he.ID != "inner" {
		t.Errorf("should unwrap to inner ID 'inner', got %q", he.ID)
	}
}
