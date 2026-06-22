package caddyconfig

import (
	"encoding/json"
	"testing"
)

func TestJSON(t *testing.T) {
	tests := []struct {
		name         string
		val          any
		wantNil      bool
		wantWarnings int
		nilWarnings  bool // pass nil warnings pointer
	}{
		{
			name:         "simple string",
			val:          "hello",
			wantNil:      false,
			wantWarnings: 0,
		},
		{
			name:         "struct",
			val:          struct{ Name string }{"test"},
			wantNil:      false,
			wantWarnings: 0,
		},
		{
			name:         "nil value",
			val:          nil,
			wantNil:      false, // json.Marshal(nil) returns "null"
			wantWarnings: 0,
		},
		{
			name:         "map",
			val:          map[string]string{"key": "val"},
			wantNil:      false,
			wantWarnings: 0,
		},
		{
			name:         "unmarshalable value produces warning",
			val:          make(chan int),
			wantNil:      true,
			wantWarnings: 1,
		},
		{
			name:        "unmarshalable value with nil warnings pointer",
			val:         make(chan int),
			wantNil:     true,
			nilWarnings: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnings *[]Warning
			if !tt.nilWarnings {
				w := []Warning{}
				warnings = &w
			}

			result := JSON(tt.val, warnings)

			if tt.wantNil && result != nil {
				t.Errorf("JSON() = %v, want nil", string(result))
			}
			if !tt.wantNil && result == nil {
				t.Error("JSON() = nil, want non-nil")
			}
			if warnings != nil && len(*warnings) != tt.wantWarnings {
				t.Errorf("JSON() produced %d warnings, want %d", len(*warnings), tt.wantWarnings)
			}
		})
	}
}

func TestJSONModuleObject(t *testing.T) {
	tests := []struct {
		name         string
		val          any
		fieldName    string
		fieldVal     string
		wantNil      bool
		wantField    bool
		wantWarnings int
	}{
		{
			name:         "simple struct",
			val:          struct{ Name string }{"test"},
			fieldName:    "handler",
			fieldVal:     "file_server",
			wantNil:      false,
			wantField:    true,
			wantWarnings: 0,
		},
		{
			name:         "map value",
			val:          map[string]any{"key": "val"},
			fieldName:    "module",
			fieldVal:     "my_module",
			wantNil:      false,
			wantField:    true,
			wantWarnings: 0,
		},
		{
			name:         "non-object type (string) produces warning",
			val:          "not-an-object",
			fieldName:    "handler",
			fieldVal:     "test",
			wantNil:      true,
			wantField:    false,
			wantWarnings: 1,
		},
		{
			name:         "unmarshalable value produces warning",
			val:          make(chan int),
			fieldName:    "handler",
			fieldVal:     "test",
			wantNil:      true,
			wantField:    false,
			wantWarnings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := []Warning{}
			result := JSONModuleObject(tt.val, tt.fieldName, tt.fieldVal, &warnings)

			if tt.wantNil && result != nil {
				t.Errorf("JSONModuleObject() = %v, want nil", string(result))
			}
			if !tt.wantNil && result == nil {
				t.Error("JSONModuleObject() = nil, want non-nil")
			}
			if len(warnings) != tt.wantWarnings {
				t.Errorf("JSONModuleObject() produced %d warnings, want %d", len(warnings), tt.wantWarnings)
			}
			if tt.wantField && result != nil {
				var m map[string]any
				if err := json.Unmarshal(result, &m); err != nil {
					t.Fatalf("failed to unmarshal result: %v", err)
				}
				if v, ok := m[tt.fieldName]; !ok {
					t.Errorf("expected field %q in result", tt.fieldName)
				} else if v != tt.fieldVal {
					t.Errorf("field %q = %v, want %v", tt.fieldName, v, tt.fieldVal)
				}
			}
		})
	}
}

func TestJSONModuleObjectPreservesExistingFields(t *testing.T) {
	val := struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}{"example", 8080}

	warnings := []Warning{}
	result := JSONModuleObject(val, "handler", "static", &warnings)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var m map[string]any
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if m["name"] != "example" {
		t.Errorf("name = %v, want 'example'", m["name"])
	}
	if m["port"] != float64(8080) {
		t.Errorf("port = %v, want 8080", m["port"])
	}
	if m["handler"] != "static" {
		t.Errorf("handler = %v, want 'static'", m["handler"])
	}
}

func TestGetAdapterNil(t *testing.T) {
	adapter := GetAdapter("nonexistent_adapter_xyz")
	if adapter != nil {
		t.Error("expected nil for unregistered adapter")
	}
}

func TestWarningString(t *testing.T) {
	tests := []struct {
		name    string
		warning Warning
		want    string
	}{
		{
			name:    "all fields",
			warning: Warning{File: "Caddyfile", Line: 10, Directive: "reverse_proxy", Message: "upstream not found"},
			want:    "Caddyfile:10 (reverse_proxy): upstream not found",
		},
		{
			name:    "no directive",
			warning: Warning{File: "Caddyfile", Line: 5, Message: "something off"},
			want:    "Caddyfile:5: something off",
		},
		{
			name:    "zero line",
			warning: Warning{File: "config.json", Line: 0, Message: "invalid"},
			want:    "config.json:0: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.warning.String()
			if got != tt.want {
				t.Errorf("Warning.String() = %q, want %q", got, tt.want)
			}
		})
	}
}
