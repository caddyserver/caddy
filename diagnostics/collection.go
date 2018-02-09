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

package diagnostics

import (
	"log"

	"github.com/google/uuid"
)

// Init initializes this package so that it may
// be used. Do not call this function more than
// once. Init panics if it is called more than
// once or if the UUID value is empty. Once this
// function is called, the rest of the package
// may safely be used. If this function is not
// called, the collector functions may still be
// invoked, but they will be no-ops.
func Init(instanceID uuid.UUID) {
	if enabled {
		panic("already initialized")
	}
	if str := instanceID.String(); str == "" ||
		instanceID.String() == "00000000-0000-0000-0000-000000000000" {
		panic("empty UUID")
	}
	instanceUUID = instanceID
	enabled = true
}

// StartEmitting sends the current payload and begins the
// transmission cycle for updates. This is the first
// update sent, and future ones will be sent until
// StopEmitting is called.
//
// This function is non-blocking (it spawns a new goroutine).
//
// This function panics if it was called more than once.
// It is a no-op if this package was not initialized.
func StartEmitting() {
	if !enabled {
		return
	}
	updateTimerMu.Lock()
	if updateTimer != nil {
		updateTimerMu.Unlock()
		panic("updates already started")
	}
	updateTimerMu.Unlock()
	updateMu.Lock()
	if updating {
		updateMu.Unlock()
		panic("update already in progress")
	}
	updateMu.Unlock()
	go logEmit(false)
}

// StopEmitting sends the current payload and terminates
// the update cycle. No more updates will be sent.
//
// It is a no-op if the package was never initialized
// or if emitting was never started.
func StopEmitting() {
	if !enabled {
		return
	}
	updateTimerMu.Lock()
	if updateTimer == nil {
		updateTimerMu.Unlock()
		return
	}
	updateTimerMu.Unlock()
	logEmit(true)
}

// Set puts a value in the buffer to be included
// in the next emission. It overwrites any
// previous value.
//
// This function is safe for multiple goroutines,
// and it is recommended to call this using the
// go keyword after the call to SendHello so it
// doesn't block crucial code.
func Set(key string, val interface{}) {
	if !enabled {
		return
	}
	bufferMu.Lock()
	if bufferItemCount >= maxBufferItems {
		bufferMu.Unlock()
		return
	}
	if _, ok := buffer[key]; !ok {
		bufferItemCount++
	}
	buffer[key] = val
	bufferMu.Unlock()
}

// Append appends value to a list named key.
// If key is new, a new list will be created.
// If key maps to a type that is not a list,
// an error is logged, and this is a no-op.
//
// TODO: is this function needed/useful?
func Append(key string, value interface{}) {
	if !enabled {
		return
	}
	bufferMu.Lock()
	if bufferItemCount >= maxBufferItems {
		bufferMu.Unlock()
		return
	}
	// TODO: Test this...
	bufVal, inBuffer := buffer[key]
	sliceVal, sliceOk := bufVal.([]interface{})
	if inBuffer && !sliceOk {
		bufferMu.Unlock()
		log.Printf("[PANIC] Diagnostics: key %s already used for non-slice value", key)
		return
	}
	if sliceVal == nil {
		buffer[key] = []interface{}{value}
	} else if sliceOk {
		buffer[key] = append(sliceVal, value)
	}
	bufferItemCount++
	bufferMu.Unlock()
}

// AppendUniqueString adds value to a set named key.
// Set items are unordered. Values in the set
// are unique, but repeat values are counted.
//
// If key is new, a new set will be created.
// If key maps to a type that is not a string
// set, an error is logged, and this is a no-op.
func AppendUniqueString(key, value string) {
	if !enabled {
		return
	}
	bufferMu.Lock()
	if bufferItemCount >= maxBufferItems {
		bufferMu.Unlock()
		return
	}
	bufVal, inBuffer := buffer[key]
	mapVal, mapOk := bufVal.(map[string]int)
	if inBuffer && !mapOk {
		bufferMu.Unlock()
		log.Printf("[PANIC] Diagnostics: key %s already used for non-map value", key)
		return
	}
	if mapVal == nil {
		buffer[key] = map[string]int{value: 1}
		bufferItemCount++
	} else if mapOk {
		mapVal[value]++
	}
	bufferMu.Unlock()
}

// AppendUniqueInt adds value to a set named key.
// Set items are unordered. Values in the set
// are unique, but repeat values are counted.
//
// If key is new, a new set will be created.
// If key maps to a type that is not an integer
// set, an error is logged, and this is a no-op.
func AppendUniqueInt(key string, value int) {
	if !enabled {
		return
	}
	bufferMu.Lock()
	if bufferItemCount >= maxBufferItems {
		bufferMu.Unlock()
		return
	}
	bufVal, inBuffer := buffer[key]
	mapVal, mapOk := bufVal.(map[int]int)
	if inBuffer && !mapOk {
		bufferMu.Unlock()
		log.Printf("[PANIC] Diagnostics: key %s already used for non-map value", key)
		return
	}
	if mapVal == nil {
		buffer[key] = map[int]int{value: 1}
		bufferItemCount++
	} else if mapOk {
		mapVal[value]++
	}
	bufferMu.Unlock()
}

// Increment adds 1 to a value named key.
// If it does not exist, it is created with
// a value of 1. If key maps to a type that
// is not an integer, an error is logged,
// and this is a no-op.
func Increment(key string) {
	incrementOrDecrement(key, true)
}

// Decrement is the same as increment except
// it subtracts 1.
func Decrement(key string) {
	incrementOrDecrement(key, false)
}

// inc == true:  increment
// inc == false: decrement
func incrementOrDecrement(key string, inc bool) {
	if !enabled {
		return
	}
	bufferMu.Lock()
	bufVal, inBuffer := buffer[key]
	intVal, intOk := bufVal.(int)
	if inBuffer && !intOk {
		bufferMu.Unlock()
		log.Printf("[PANIC] Diagnostics: key %s already used for non-integer value", key)
		return
	}
	if !inBuffer {
		if bufferItemCount >= maxBufferItems {
			bufferMu.Unlock()
			return
		}
		bufferItemCount++
	}
	if inc {
		buffer[key] = intVal + 1
	} else {
		buffer[key] = intVal - 1
	}
	bufferMu.Unlock()
}
