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
	"encoding/json"
	"testing"
)

func TestMakePayloadAndResetBuffer(t *testing.T) {
	reset()
	id := doInit(t)

	buffer = map[string]interface{}{
		"foo1": "bar1",
		"foo2": "bar2",
	}
	bufferItemCount = 2

	payloadBytes, err := makePayloadAndResetBuffer()
	if err != nil {
		t.Fatalf("Error making payload bytes: %v", err)
	}

	if len(buffer) != 0 {
		t.Errorf("Expected buffer len to be 0, got %d", len(buffer))
	}
	if bufferItemCount != 0 {
		t.Errorf("Expected buffer item count to be 0, got %d", bufferItemCount)
	}

	var payload Payload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		t.Fatalf("Error deserializing payload: %v", err)
	}

	if payload.InstanceID != id.String() {
		t.Errorf("Expected instance ID to be set to '%s' but got '%s'", testUUID, payload.InstanceID)
	}
	if payload.Data == nil {
		t.Errorf("Expected data to be set, but was nil")
	}
	if payload.Timestamp.IsZero() {
		t.Errorf("Expected timestamp to be set, but was zero value")
	}
}
