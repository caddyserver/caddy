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
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewEvent_Basic(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	eventName := "test.event"
	eventData := map[string]any{
		"key1": "value1",
		"key2": 42,
	}

	event, err := NewEvent(ctx, eventName, eventData)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	// Verify event properties
	if event.Name() != eventName {
		t.Errorf("Expected name '%s', got '%s'", eventName, event.Name())
	}

	if event.Data == nil {
		t.Error("Expected non-nil data")
	}

	if len(event.Data) != len(eventData) {
		t.Errorf("Expected %d data items, got %d", len(eventData), len(event.Data))
	}

	for key, expectedValue := range eventData {
		if actualValue, exists := event.Data[key]; !exists || actualValue != expectedValue {
			t.Errorf("Data key '%s': expected %v, got %v", key, expectedValue, actualValue)
		}
	}

	// Verify ID is generated
	if event.ID().String() == "" {
		t.Error("Event ID should not be empty")
	}

	// Verify timestamp is recent
	if time.Since(event.Timestamp()) > time.Second {
		t.Error("Event timestamp should be recent")
	}
}

func TestNewEvent_NameNormalization(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	tests := []struct {
		input    string
		expected string
	}{
		{"UPPERCASE", "uppercase"},
		{"MixedCase", "mixedcase"},
		{"already.lower", "already.lower"},
		{"With-Dashes", "with-dashes"},
		{"With_Underscores", "with_underscores"},
		{"", ""},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			event, err := NewEvent(ctx, test.input, nil)
			if err != nil {
				t.Fatalf("Failed to create event: %v", err)
			}

			if event.Name() != test.expected {
				t.Errorf("Expected normalized name '%s', got '%s'", test.expected, event.Name())
			}
		})
	}
}

func TestEvent_CloudEvent_NilData(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	event, err := NewEvent(ctx, "test", nil)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	cloudEvent := event.CloudEvent()

	// Should not panic with nil data
	if cloudEvent.Data == nil {
		t.Error("CloudEvent data should not be nil even with nil input")
	}

	// Should be valid JSON
	var parsed any
	if err := json.Unmarshal(cloudEvent.Data, &parsed); err != nil {
		t.Errorf("CloudEvent data should be valid JSON: %v", err)
	}
}

func TestEvent_CloudEvent_WithModule(t *testing.T) {
	// Create a context with a mock module
	mockMod := &mockModule{}
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	// Simulate module ancestry
	ctx.ancestry = []Module{mockMod}

	event, err := NewEvent(ctx, "test", nil)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	cloudEvent := event.CloudEvent()

	// Source should be the module ID
	expectedSource := string(mockMod.CaddyModule().ID)
	if cloudEvent.Source != expectedSource {
		t.Errorf("Expected source '%s', got '%s'", expectedSource, cloudEvent.Source)
	}

	// Origin should be the module
	if event.Origin() != mockMod {
		t.Error("Expected event origin to be the mock module")
	}
}

func TestEvent_CloudEvent_Fields(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	eventName := "test.event"
	eventData := map[string]any{"test": "data"}

	event, err := NewEvent(ctx, eventName, eventData)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	cloudEvent := event.CloudEvent()

	// Verify CloudEvent fields
	if cloudEvent.ID == "" {
		t.Error("CloudEvent ID should not be empty")
	}

	if cloudEvent.Source != "caddy" {
		t.Errorf("Expected source 'caddy' for nil module, got '%s'", cloudEvent.Source)
	}

	if cloudEvent.SpecVersion != "1.0" {
		t.Errorf("Expected spec version '1.0', got '%s'", cloudEvent.SpecVersion)
	}

	if cloudEvent.Type != eventName {
		t.Errorf("Expected type '%s', got '%s'", eventName, cloudEvent.Type)
	}

	if cloudEvent.DataContentType != "application/json" {
		t.Errorf("Expected content type 'application/json', got '%s'", cloudEvent.DataContentType)
	}

	// Verify data is valid JSON
	var parsedData map[string]any
	if err := json.Unmarshal(cloudEvent.Data, &parsedData); err != nil {
		t.Errorf("CloudEvent data is not valid JSON: %v", err)
	}

	if parsedData["test"] != "data" {
		t.Errorf("Expected data to contain test='data', got %v", parsedData)
	}
}

func TestEvent_ConcurrentAccess(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	event, err := NewEvent(ctx, "concurrent.test", map[string]any{
		"counter": 0,
		"data":    "shared",
	})
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup

	// Test concurrent read access to event properties
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// These should be safe for concurrent access
			_ = event.ID()
			_ = event.Name()
			_ = event.Timestamp()
			_ = event.Origin()
			_ = event.CloudEvent()

			// Data map is not synchronized, so read-only access should be safe
			if data, exists := event.Data["data"]; !exists || data != "shared" {
				t.Errorf("Goroutine %d: Expected shared data", id)
			}
		}(i)
	}

	wg.Wait()
}

func TestEvent_DataModification_Warning(t *testing.T) {
	// This test documents the non-thread-safe nature of event data
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	event, err := NewEvent(ctx, "data.test", map[string]any{
		"mutable": "original",
	})
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	// Modifying data after creation (this is allowed but not thread-safe)
	event.Data["mutable"] = "modified"
	event.Data["new_key"] = "new_value"

	// Verify modifications are visible
	if event.Data["mutable"] != "modified" {
		t.Error("Data modification should be visible")
	}
	if event.Data["new_key"] != "new_value" {
		t.Error("New data should be visible")
	}

	// CloudEvent should reflect the current state
	cloudEvent := event.CloudEvent()
	var parsedData map[string]any
	json.Unmarshal(cloudEvent.Data, &parsedData)

	if parsedData["mutable"] != "modified" {
		t.Error("CloudEvent should reflect modified data")
	}
	if parsedData["new_key"] != "new_value" {
		t.Error("CloudEvent should reflect new data")
	}
}

func TestEvent_Aborted_State(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	event, err := NewEvent(ctx, "abort.test", nil)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	// Initially not aborted
	if event.Aborted != nil {
		t.Error("Event should not be aborted initially")
	}

	// Simulate aborting the event
	event.Aborted = ErrEventAborted

	if event.Aborted != ErrEventAborted {
		t.Error("Event should be marked as aborted")
	}
}

func TestErrEventAborted_Value(t *testing.T) {
	if ErrEventAborted == nil {
		t.Error("ErrEventAborted should not be nil")
	}

	if ErrEventAborted.Error() != "event aborted" {
		t.Errorf("Expected 'event aborted', got '%s'", ErrEventAborted.Error())
	}
}

func TestEvent_UniqueIDs(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	const numEvents = 1000
	ids := make(map[string]bool)

	for i := 0; i < numEvents; i++ {
		event, err := NewEvent(ctx, "unique.test", nil)
		if err != nil {
			t.Fatalf("Failed to create event %d: %v", i, err)
		}

		idStr := event.ID().String()
		if ids[idStr] {
			t.Errorf("Duplicate event ID: %s", idStr)
		}
		ids[idStr] = true
	}
}

func TestEvent_TimestampProgression(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	// Create events with small delays
	events := make([]Event, 5)
	for i := range events {
		var err error
		events[i], err = NewEvent(ctx, "time.test", nil)
		if err != nil {
			t.Fatalf("Failed to create event %d: %v", i, err)
		}

		if i < len(events)-1 {
			time.Sleep(time.Millisecond)
		}
	}

	// Verify timestamps are in ascending order
	for i := 1; i < len(events); i++ {
		if !events[i].Timestamp().After(events[i-1].Timestamp()) {
			t.Errorf("Event %d timestamp (%v) should be after event %d timestamp (%v)",
				i, events[i].Timestamp(), i-1, events[i-1].Timestamp())
		}
	}
}

func TestEvent_JSON_Serialization(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	eventData := map[string]any{
		"string":  "value",
		"number":  42,
		"boolean": true,
		"array":   []any{1, 2, 3},
		"object":  map[string]any{"nested": "value"},
	}

	event, err := NewEvent(ctx, "json.test", eventData)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	cloudEvent := event.CloudEvent()

	// CloudEvent should be JSON serializable
	cloudEventJSON, err := json.Marshal(cloudEvent)
	if err != nil {
		t.Fatalf("Failed to marshal CloudEvent: %v", err)
	}

	// Should be able to unmarshal back
	var parsed CloudEvent
	err = json.Unmarshal(cloudEventJSON, &parsed)
	if err != nil {
		t.Fatalf("Failed to unmarshal CloudEvent: %v", err)
	}

	// Verify key fields survived round-trip
	if parsed.ID != cloudEvent.ID {
		t.Errorf("ID mismatch after round-trip")
	}
	if parsed.Source != cloudEvent.Source {
		t.Errorf("Source mismatch after round-trip")
	}
	if parsed.Type != cloudEvent.Type {
		t.Errorf("Type mismatch after round-trip")
	}
}

func TestEvent_EmptyData(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	// Test with empty map
	event1, err := NewEvent(ctx, "empty.map", map[string]any{})
	if err != nil {
		t.Fatalf("Failed to create event with empty map: %v", err)
	}

	cloudEvent1 := event1.CloudEvent()
	var parsed1 map[string]any
	json.Unmarshal(cloudEvent1.Data, &parsed1)
	if len(parsed1) != 0 {
		t.Error("Expected empty data map")
	}

	// Test with nil data
	event2, err := NewEvent(ctx, "nil.data", nil)
	if err != nil {
		t.Fatalf("Failed to create event with nil data: %v", err)
	}

	cloudEvent2 := event2.CloudEvent()
	if cloudEvent2.Data == nil {
		t.Error("CloudEvent data should not be nil even with nil input")
	}
}

func TestEvent_Origin_WithModule(t *testing.T) {
	mockMod := &mockEventModule{}
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	// Set module in ancestry
	ctx.ancestry = []Module{mockMod}

	event, err := NewEvent(ctx, "module.test", nil)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	if event.Origin() != mockMod {
		t.Error("Expected event origin to be the mock module")
	}

	cloudEvent := event.CloudEvent()
	expectedSource := string(mockMod.CaddyModule().ID)
	if cloudEvent.Source != expectedSource {
		t.Errorf("Expected source '%s', got '%s'", expectedSource, cloudEvent.Source)
	}
}

func TestEvent_LargeData(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	// Create event with large data
	largeData := make(map[string]any)
	for i := 0; i < 1000; i++ {
		largeData[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	event, err := NewEvent(ctx, "large.data", largeData)
	if err != nil {
		t.Fatalf("Failed to create event with large data: %v", err)
	}

	// CloudEvent should handle large data
	cloudEvent := event.CloudEvent()

	var parsedData map[string]any
	err = json.Unmarshal(cloudEvent.Data, &parsedData)
	if err != nil {
		t.Fatalf("Failed to parse large data in CloudEvent: %v", err)
	}

	if len(parsedData) != len(largeData) {
		t.Errorf("Expected %d data items, got %d", len(largeData), len(parsedData))
	}
}

func TestEvent_SpecialCharacters_InData(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	specialData := map[string]any{
		"unicode":     "🚀✨",
		"newlines":    "line1\nline2\r\nline3",
		"quotes":      `"double" and 'single' quotes`,
		"backslashes": "\\path\\to\\file",
		"json_chars":  `{"key": "value"}`,
		"empty":       "",
		"null_value":  nil,
	}

	event, err := NewEvent(ctx, "special.chars", specialData)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	cloudEvent := event.CloudEvent()

	// Should produce valid JSON
	var parsedData map[string]any
	err = json.Unmarshal(cloudEvent.Data, &parsedData)
	if err != nil {
		t.Fatalf("Failed to parse data with special characters: %v", err)
	}

	// Verify some special cases survived JSON round-trip
	if parsedData["unicode"] != "🚀✨" {
		t.Error("Unicode characters should survive JSON encoding")
	}

	if parsedData["quotes"] != `"double" and 'single' quotes` {
		t.Error("Quotes should be properly escaped in JSON")
	}
}

func TestEvent_ConcurrentCreation(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	const numGoroutines = 100
	var wg sync.WaitGroup
	events := make([]Event, numGoroutines)
	errors := make([]error, numGoroutines)

	// Create events concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			eventData := map[string]any{
				"goroutine": index,
				"timestamp": time.Now().UnixNano(),
			}

			events[index], errors[index] = NewEvent(ctx, "concurrent.test", eventData)
		}(i)
	}

	wg.Wait()

	// Verify all events were created successfully
	ids := make(map[string]bool)
	for i, event := range events {
		if errors[i] != nil {
			t.Errorf("Goroutine %d: Failed to create event: %v", i, errors[i])
			continue
		}

		// Verify unique IDs
		idStr := event.ID().String()
		if ids[idStr] {
			t.Errorf("Duplicate event ID: %s", idStr)
		}
		ids[idStr] = true

		// Verify data integrity
		if goroutineID, exists := event.Data["goroutine"]; !exists || goroutineID != i {
			t.Errorf("Event %d: Data corruption detected", i)
		}
	}
}

// Mock module for event testing
type mockEventModule struct{}

func (m *mockEventModule) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "test.event.module",
		New: func() Module { return new(mockEventModule) },
	}
}

func TestEvent_TimeAccuracy(t *testing.T) {
	before := time.Now()

	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	event, err := NewEvent(ctx, "time.accuracy", nil)
	if err != nil {
		t.Fatalf("Failed to create event: %v", err)
	}

	after := time.Now()
	eventTime := event.Timestamp()

	// Event timestamp should be between before and after
	if eventTime.Before(before) || eventTime.After(after) {
		t.Errorf("Event timestamp %v should be between %v and %v", eventTime, before, after)
	}
}

func BenchmarkNewEvent(b *testing.B) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	eventData := map[string]any{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEvent(ctx, "benchmark.test", eventData)
	}
}

func BenchmarkEvent_CloudEvent(b *testing.B) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	event, _ := NewEvent(ctx, "benchmark.cloud", map[string]any{
		"data": "test",
		"num":  123,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.CloudEvent()
	}
}

func BenchmarkEvent_CloudEvent_LargeData(b *testing.B) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	defer cancel()

	// Create event with substantial data
	largeData := make(map[string]any)
	for i := 0; i < 100; i++ {
		largeData[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	event, _ := NewEvent(ctx, "benchmark.large", largeData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.CloudEvent()
	}
}
