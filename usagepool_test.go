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
	"errors"
	"testing"
	"time"
)

func TestUsagePoolFailedConstructorDoesNotInvertLocks(t *testing.T) {
	pool := NewUsagePool()
	constructorStarted := make(chan struct{})
	finishConstructor := make(chan struct{})
	loadResult := make(chan error, 1)
	constructErr := errors.New("construction failed")

	go func() {
		_, _, err := pool.LoadOrNew("key", func() (Destructor, error) {
			close(constructorStarted)
			<-finishConstructor
			return nil, constructErr
		})
		loadResult <- err
	}()

	<-constructorStarted
	pool.RLock()
	entry := pool.pool["key"]
	close(finishConstructor)

	entryReadable := make(chan struct{})
	go func() {
		entry.RLock()
		entry.RUnlock()
		close(entryReadable)
	}()

	select {
	case <-entryReadable:
		pool.RUnlock()
	case <-time.After(time.Second):
		pool.RUnlock()
		<-loadResult
		t.Fatal("failed constructor held the entry lock while waiting for the pool lock")
	}

	if err := <-loadResult; !errors.Is(err, constructErr) {
		t.Fatalf("LoadOrNew() error = %v, want %v", err, constructErr)
	}
}
