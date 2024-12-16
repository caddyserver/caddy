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
// based on usage (reference counting). Values are
// only inserted if they do not already exist. There
// are two ways to add values to the pool:
//
//  1. LoadOrStore will increment usage and store the
//     value immediately if it does not already exist.
//  2. LoadOrNew will atomically check for existence
//     and construct the value immediately if it does
//     not already exist, or increment the usage
//     otherwise, then store that value in the pool.
//     When the constructed value is finally deleted
//     from the pool (when its usage reaches 0), it
//     will be cleaned up by calling Destruct().
//
// The use of LoadOrNew allows values to be created
// and reused and finally cleaned up only once, even
// though they may have many references throughout
// their lifespan. This is helpful, for example, when
// sharing thread-safe io.Writers that you only want
// to open and close once.
//
// There is no way to overwrite existing keys in the
// pool without first deleting it as many times as it
// was stored. Deleting too many times will panic.
//
// The implementation does not use a sync.Pool because
// UsagePool needs additional atomicity to run the
// constructor functions when creating a new value when
// LoadOrNew is used. (We could probably use sync.Pool
// but we'd still have to layer our own additional locks
// on top.)
//
// An empty UsagePool is NOT safe to use; always call
// NewUsagePool() to make a new one.
type UsagePool struct {
	sync.RWMutex
	pool map[any]*usagePoolVal
}

// NewUsagePool returns a new usage pool that is ready to use.
func NewUsagePool() *UsagePool {
	return &UsagePool{
		pool: make(map[any]*usagePoolVal),
	}
}

// LoadOrNew loads the value associated with key from the pool if it
// already exists. If the key doesn't exist, it will call construct
// to create a new value and then stores that in the pool. An error
// is only returned if the constructor returns an error. The loaded
// or constructed value is returned. The loaded return value is true
// if the value already existed and was loaded, or false if it was
// newly constructed.
func (up *UsagePool) LoadOrNew(key any, construct Constructor) (value any, loaded bool, err error) {
	var upv *usagePoolVal
	up.Lock()
	upv, loaded = up.pool[key]
	if loaded {
		atomic.AddInt32(&upv.refs, 1)
		up.Unlock()
		upv.RLock()
		value = upv.value
		err = upv.err
		upv.RUnlock()
	} else {
		upv = &usagePoolVal{refs: 1}
		upv.Lock()
		up.pool[key] = upv
		up.Unlock()
		value, err = construct()
		if err == nil {
			upv.value = value
		} else {
			upv.err = err
			up.Lock()
			// this *should* be safe, I think, because we have a
			// write lock on upv, but we might also need to ensure
			// that upv.err is nil before doing this, since we
			// released the write lock on up during construct...
			// but then again it's also after midnight...
			delete(up.pool, key)
			up.Unlock()
		}
		upv.Unlock()
	}
	return
}

// LoadOrStore loads the value associated with key from the pool if it
// already exists, or stores it if it does not exist. It returns the
// value that was either loaded or stored, and true if the value already
// existed and was loaded, false if the value didn't exist and was stored.
func (up *UsagePool) LoadOrStore(key, val any) (value any, loaded bool) {
	var upv *usagePoolVal
	up.Lock()
	upv, loaded = up.pool[key]
	if loaded {
		atomic.AddInt32(&upv.refs, 1)
		up.Unlock()
		upv.Lock()
		if upv.err == nil {
			value = upv.value
		} else {
			upv.value = val
			upv.err = nil
		}
		upv.Unlock()
	} else {
		upv = &usagePoolVal{refs: 1, value: val}
		up.pool[key] = upv
		up.Unlock()
		value = val
	}
	return
}

// Range iterates the pool similarly to how sync.Map.Range() does:
// it calls f for every key in the pool, and if f returns false,
// iteration is stopped. Ranging does not affect usage counts.
//
// This method is somewhat naive and acquires a read lock on the
// entire pool during iteration, so do your best to make f() really
// fast, m'kay?
func (up *UsagePool) Range(f func(key, value any) bool) {
	up.RLock()
	defer up.RUnlock()
	for key, upv := range up.pool {
		upv.RLock()
		if upv.err != nil {
			upv.RUnlock()
			continue
		}
		val := upv.value
		upv.RUnlock()
		if !f(key, val) {
			break
		}
	}
}

// Delete decrements the usage count for key and removes the
// value from the underlying map if the usage is 0. It returns
// true if the usage count reached 0 and the value was deleted.
// It panics if the usage count drops below 0; always call
// Delete precisely as many times as LoadOrStore.
func (up *UsagePool) Delete(key any) (deleted bool, err error) {
	up.Lock()
	upv, ok := up.pool[key]
	if !ok {
		up.Unlock()
		return false, nil
	}
	refs := atomic.AddInt32(&upv.refs, -1)
	if refs == 0 {
		delete(up.pool, key)
		up.Unlock()
		upv.RLock()
		val := upv.value
		upv.RUnlock()
		if destructor, ok := val.(Destructor); ok {
			err = destructor.Destruct()
		}
		deleted = true
	} else {
		up.Unlock()
		if refs < 0 {
			panic(fmt.Sprintf("deleted more than stored: %#v (usage: %d)",
				upv.value, upv.refs))
		}
	}
	return
}

// References returns the number of references (count of usages) to a
// key in the pool, and true if the key exists, or false otherwise.
func (up *UsagePool) References(key any) (int, bool) {
	up.RLock()
	upv, loaded := up.pool[key]
	up.RUnlock()
	if loaded {
		// I wonder if it'd be safer to read this value during
		// our lock on the UsagePool... guess we'll see...
		refs := atomic.LoadInt32(&upv.refs)
		return int(refs), true
	}
	return 0, false
}

// Constructor is a function that returns a new value
// that can destruct itself when it is no longer needed.
type Constructor func() (Destructor, error)

// Destructor is a value that can clean itself up when
// it is deallocated.
type Destructor interface {
	Destruct() error
}

type usagePoolVal struct {
	refs  int32 // accessed atomically; must be 64-bit aligned for 32-bit systems
	value any
	err   error
	sync.RWMutex
}
