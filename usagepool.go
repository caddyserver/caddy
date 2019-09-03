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
	"fmt"
	"sync"
	"sync/atomic"
)

// UsagePool is a thread-safe map that pools values
// based on usage; a LoadOrStore operation increments
// the usage, and a Delete decrements from the usage.
// If the usage count reaches 0, the value will be
// removed from the map. There is no way to overwrite
// existing keys in the pool without first deleting
// it as many times as it was stored. Deleting too
// many times will panic.
//
// An empty UsagePool is NOT safe to use; always call
// NewUsagePool() to make a new value.
type UsagePool struct {
	pool *sync.Map
}

// NewUsagePool returns a new usage pool.
func NewUsagePool() *UsagePool {
	return &UsagePool{pool: new(sync.Map)}
}

// Delete decrements the usage count for key and removes the
// value from the underlying map if the usage is 0. It returns
// true if the usage count reached 0 and the value was deleted.
// It panics if the usage count drops below 0; always call
// Delete precisely as many times as LoadOrStore.
func (up *UsagePool) Delete(key interface{}) (deleted bool) {
	usageVal, ok := up.pool.Load(key)
	if !ok {
		return false
	}
	upv := usageVal.(*usagePoolVal)
	newUsage := atomic.AddInt32(&upv.usage, -1)
	if newUsage == 0 {
		up.pool.Delete(key)
		return true
	} else if newUsage < 0 {
		panic(fmt.Sprintf("deleted more than stored: %#v (usage: %d)",
			upv.value, upv.usage))
	}
	return false
}

// LoadOrStore puts val in the pool and returns false if key does
// not already exist; otherwise if the key exists, it loads the
// existing value, increments the usage for that value, and returns
// the value along with true.
func (up *UsagePool) LoadOrStore(key, val interface{}) (actual interface{}, loaded bool) {
	usageVal := &usagePoolVal{
		usage: 1,
		value: val,
	}
	actual, loaded = up.pool.LoadOrStore(key, usageVal)
	if loaded {
		upv := actual.(*usagePoolVal)
		actual = upv.value
		atomic.AddInt32(&upv.usage, 1)
	}
	return
}

// Range iterates the pool the same way sync.Map.Range does.
// This does not affect usage counts.
func (up *UsagePool) Range(f func(key, value interface{}) bool) {
	up.pool.Range(func(key, value interface{}) bool {
		return f(key, value.(*usagePoolVal).value)
	})
}

type usagePoolVal struct {
	usage int32 // accessed atomically; must be 64-bit aligned for 32-bit systems
	value interface{}
}
