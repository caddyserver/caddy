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

// Package diagnostics implements the client for server-side diagnostics
// of the network. Functions in this package are synchronous and blocking
// unless otherwise specified. For convenience, most functions here do
// not return errors, but errors are logged to the standard logger.
//
// To use this package, first call Init(). You can then call any of the
// collection/aggregation functions. Call StartEmitting() when you are
// ready to begin sending diagnostic updates.
//
// When collecting metrics (functions like Set, Append*, or Increment),
// it may be desirable and even recommended to run invoke them in a new
// goroutine (use the go keyword) in case there is lock contention;
// they are thread-safe (unless noted), and you may not want them to
// block the main thread of execution. However, sometimes blocking
// may be necessary too; for example, adding startup metrics to the
// buffer before the call to StartEmitting().
package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// logEmit calls emit and then logs the error, if any.
func logEmit(final bool) {
	err := emit(final)
	if err != nil {
		log.Printf("[ERROR] Sending diganostics: %v", err)
	}
}

// emit sends an update to the diagnostics server.
// If final is true, no future updates will be scheduled.
// Otherwise, the next update will be scheduled.
func emit(final bool) error {
	if !enabled {
		return fmt.Errorf("diagnostics not enabled")
	}

	// ensure only one update happens at a time;
	// skip update if previous one still in progress
	updateMu.Lock()
	if updating {
		updateMu.Unlock()
		log.Println("[NOTICE] Skipping this diagnostics update because previous one is still working")
		return nil
	}
	updating = true
	updateMu.Unlock()
	defer func() {
		updateMu.Lock()
		updating = false
		updateMu.Unlock()
	}()

	// terminate any pending update if this is the last one
	if final {
		updateTimerMu.Lock()
		updateTimer.Stop()
		updateTimer = nil
		updateTimerMu.Unlock()
	}

	payloadBytes, err := makePayloadAndResetBuffer()
	if err != nil {
		return err
	}

	// this will hold the server's reply
	var reply Response

	// transmit the payload - use a loop to retry in case of failure
	for i := 0; i < 4; i++ {
		if i > 0 && err != nil {
			// don't hammer the server; first failure might have been
			// a fluke, but back off more after that
			log.Printf("[WARNING] Sending diagnostics (attempt %d): %v - waiting and retrying", i, err)
			time.Sleep(time.Duration(i*i*i) * time.Second)
		}

		// send it
		var resp *http.Response
		resp, err = httpClient.Post(endpoint+instanceUUID.String(), "application/json", bytes.NewReader(payloadBytes))
		if err != nil {
			continue
		}

		// ensure we can read the response
		if ct := resp.Header.Get("Content-Type"); (resp.StatusCode < 300 || resp.StatusCode >= 400) &&
			!strings.Contains(ct, "json") {
			err = fmt.Errorf("diagnostics server replied with unknown content-type: %s", ct)
			resp.Body.Close()
			continue
		}

		// read the response body
		err = json.NewDecoder(resp.Body).Decode(&reply)
		resp.Body.Close() // close response body as soon as we're done with it
		if err != nil {
			continue
		}

		// ensure we won't slam the diagnostics server
		if reply.NextUpdate < 1*time.Second {
			reply.NextUpdate = defaultUpdateInterval
		}

		// make sure we didn't send the update too soon; if so,
		// just wait and try again -- this is a special case of
		// error that we handle differently, as you can see
		if resp.StatusCode == http.StatusTooManyRequests {
			log.Printf("[NOTICE] Sending diagnostics: we were too early; waiting %s before trying again", reply.NextUpdate)
			time.Sleep(reply.NextUpdate)
			continue
		} else if resp.StatusCode >= 400 {
			err = fmt.Errorf("diagnostics server returned status code %d", resp.StatusCode)
			continue
		}

		break
	}
	if err == nil {
		// (remember, if there was an error, we return it
		// below, so it will get logged if it's supposed to)
		log.Println("[INFO] Sending diagnostics: success")
	}

	// even if there was an error after retrying, we should
	// schedule the next update using our default update
	// interval because the server might be healthy later

	// schedule the next update (if this wasn't the last one and
	// if the remote server didn't tell us to stop sending)
	if !final && !reply.Stop {
		updateTimerMu.Lock()
		updateTimer = time.AfterFunc(reply.NextUpdate, func() {
			logEmit(false)
		})
		updateTimerMu.Unlock()
	}

	return err
}

// makePayloadAndResetBuffer prepares a payload
// by emptying the collection buffer. It returns
// the bytes of the payload to send to the server.
// Since the buffer is reset by this, if the
// resulting byte slice is lost, the payload is
// gone with it.
func makePayloadAndResetBuffer() ([]byte, error) {
	// make a local pointer to the buffer, then reset
	// the buffer to an empty map to clear it out
	bufferMu.Lock()
	bufCopy := buffer
	buffer = make(map[string]interface{})
	bufferItemCount = 0
	bufferMu.Unlock()

	// encode payload in preparation for transmission
	payload := Payload{
		InstanceID: instanceUUID.String(),
		Timestamp:  time.Now().UTC(),
		Data:       bufCopy,
	}
	return json.Marshal(payload)
}

// Response contains the body of a response from the
// diagnostics server.
type Response struct {
	// NextUpdate is how long to wait before the next update.
	NextUpdate time.Duration `json:"next_update"`

	// Stop instructs the diagnostics server to stop sending
	// diagnostics. This would only be done under extenuating
	// circumstances, but we are prepared for it nonetheless.
	Stop bool `json:"stop,omitempty"`

	// Error will be populated with an error message, if any.
	// This field should be empty if the status code is < 400.
	Error string `json:"error,omitempty"`
}

// Payload is the data that gets sent to the diagnostics server.
type Payload struct {
	// The universally unique ID of the instance
	InstanceID string `json:"instance_id"`

	// The UTC timestamp of the transmission
	Timestamp time.Time `json:"timestamp"`

	// The metrics
	Data map[string]interface{} `json:"data,omitempty"`
}

var (
	// httpClient should be used for HTTP requests. It
	// is configured with a timeout for reliability.
	httpClient = http.Client{Timeout: 1 * time.Minute}

	// buffer holds the data that we are building up to send.
	buffer          = make(map[string]interface{})
	bufferItemCount = 0
	bufferMu        sync.RWMutex // protects both the buffer and its count

	// updating is used to ensure only one
	// update happens at a time.
	updating bool
	updateMu sync.Mutex

	// updateTimer fires off the next update.
	// If no update is scheduled, this is nil.
	updateTimer   *time.Timer
	updateTimerMu sync.Mutex

	// instanceUUID is the ID of the current instance.
	// This MUST be set to emit diagnostics.
	instanceUUID uuid.UUID

	// enabled indicates whether the package has
	// been initialized and can be actively used.
	enabled bool

	// maxBufferItems is the maximum number of items we'll allow
	// in the buffer before we start dropping new ones, in a
	// rough (simple) attempt to keep memory use under control.
	maxBufferItems = 100000
)

const (
	// endpoint is the base URL to remote diagnostics server;
	// the instance ID will be appended to it.
	endpoint = "https://diagnostics-staging.caddyserver.com/update/" // TODO: make configurable, "http://localhost:8081/update/"

	// defaultUpdateInterval is how long to wait before emitting
	// more diagnostic data. This value is only used if the
	// client receives a nonsensical value, or doesn't send one
	// at all, indicating a likely problem with the server. Thus,
	// this value should be a long duration to help alleviate
	// extra load on the server.
	defaultUpdateInterval = 1 * time.Hour
)
