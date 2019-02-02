// Copyright 2015 Light Code Labs, LLC
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

package telemetry

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestInit(t *testing.T) {
	reset()

	id := doInit(t) // should not panic

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Second call to Init should have panicked")
		}
	}()
	Init(id, nil) // should panic
}

func TestInitEmptyUUID(t *testing.T) {
	reset()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Call to Init with empty UUID should have panicked")
		}
	}()
	Init(uuid.UUID([16]byte{}), nil)
}

func TestSet(t *testing.T) {
	reset()

	// should be no-op since we haven't called Init() yet
	Set("test1", "foobar")
	if _, ok := buffer["test"]; ok {
		t.Errorf("Should not have inserted item when not initialized")
	}

	// should work after we've initialized
	doInit(t)
	Set("test1", "foobar")
	val, ok := buffer["test1"]
	if !ok {
		t.Errorf("Expected value to be in buffer, but it wasn't")
	} else if val.(string) != "foobar" {
		t.Errorf("Expected 'foobar', got '%v'", val)
	}

	// should not overfill buffer
	maxBufferItemsTmp := maxBufferItems
	maxBufferItems = 10
	for i := 0; i < maxBufferItems+1; i++ {
		Set(fmt.Sprintf("overfill_%d", i), "foobar")
	}
	if len(buffer) > maxBufferItems {
		t.Errorf("Should not exceed max buffer size (%d); has %d items",
			maxBufferItems, len(buffer))
	}
	maxBufferItems = maxBufferItemsTmp

	// Should overwrite values
	Set("test1", "foobar2")
	val, ok = buffer["test1"]
	if !ok {
		t.Errorf("Expected value to be in buffer, but it wasn't")
	} else if val.(string) != "foobar2" {
		t.Errorf("Expected 'foobar2', got '%v'", val)
	}
}

// doInit calls Init() with a valid UUID
// and returns it.
func doInit(t *testing.T) uuid.UUID {
	id, err := uuid.Parse(testUUID)
	if err != nil {
		t.Fatalf("Could not make UUID: %v", err)
	}
	Init(id, nil)
	return id
}

// reset resets all the lovely package-level state;
// can be used as a set up function in tests.
func reset() {
	instanceUUID = uuid.UUID{}
	buffer = make(map[string]interface{})
	bufferItemCount = 0
	updating = false
	enabled = false
}

const testUUID = "0b6cfa22-0d4c-11e8-b11b-7a0058e13201"
