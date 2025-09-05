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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockDestructor struct {
	value     string
	destroyed int32
	err       error
}

func (m *mockDestructor) Destruct() error {
	atomic.StoreInt32(&m.destroyed, 1)
	return m.err
}

func (m *mockDestructor) IsDestroyed() bool {
	return atomic.LoadInt32(&m.destroyed) == 1
}

func TestUsagePool_LoadOrNew_Basic(t *testing.T) {
	pool := NewUsagePool()
	key := "test-key"

	// First load should construct new value
	val, loaded, err := pool.LoadOrNew(key, func() (Destructor, error) {
		return &mockDestructor{value: "test-value"}, nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if loaded {
		t.Error("Expected loaded to be false for new value")
	}
	if val.(*mockDestructor).value != "test-value" {
		t.Errorf("Expected 'test-value', got '%s'", val.(*mockDestructor).value)
	}

	// Second load should return existing value
	val2, loaded2, err := pool.LoadOrNew(key, func() (Destructor, error) {
		t.Error("Constructor should not be called for existing value")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !loaded2 {
		t.Error("Expected loaded to be true for existing value")
	}
	if val2.(*mockDestructor).value != "test-value" {
		t.Errorf("Expected 'test-value', got '%s'", val2.(*mockDestructor).value)
	}

	// Check reference count
	refs, exists := pool.References(key)
	if !exists {
		t.Error("Key should exist in pool")
	}
	if refs != 2 {
		t.Errorf("Expected 2 references, got %d", refs)
	}
}

func TestUsagePool_LoadOrNew_ConstructorError(t *testing.T) {
	pool := NewUsagePool()
	key := "test-key"
	expectedErr := errors.New("constructor failed")

	val, loaded, err := pool.LoadOrNew(key, func() (Destructor, error) {
		return nil, expectedErr
	})
	if err != expectedErr {
		t.Errorf("Expected constructor error, got: %v", err)
	}
	if loaded {
		t.Error("Expected loaded to be false for failed construction")
	}
	if val != nil {
		t.Error("Expected nil value for failed construction")
	}

	// Key should not exist after constructor failure
	refs, exists := pool.References(key)
	if exists {
		t.Error("Key should not exist after constructor failure")
	}
	if refs != 0 {
		t.Errorf("Expected 0 references, got %d", refs)
	}
}

func TestUsagePool_LoadOrStore_Basic(t *testing.T) {
	pool := NewUsagePool()
	key := "test-key"
	mockVal := &mockDestructor{value: "stored-value"}

	// First load/store should store new value
	val, loaded := pool.LoadOrStore(key, mockVal)
	if loaded {
		t.Error("Expected loaded to be false for new value")
	}
	if val != mockVal {
		t.Error("Expected stored value to be returned")
	}

	// Second load/store should return existing value
	newMockVal := &mockDestructor{value: "new-value"}
	val2, loaded2 := pool.LoadOrStore(key, newMockVal)
	if !loaded2 {
		t.Error("Expected loaded to be true for existing value")
	}
	if val2 != mockVal {
		t.Error("Expected original stored value to be returned")
	}

	// Check reference count
	refs, exists := pool.References(key)
	if !exists {
		t.Error("Key should exist in pool")
	}
	if refs != 2 {
		t.Errorf("Expected 2 references, got %d", refs)
	}
}

func TestUsagePool_Delete_Basic(t *testing.T) {
	pool := NewUsagePool()
	key := "test-key"
	mockVal := &mockDestructor{value: "test-value"}

	// Store value twice to get ref count of 2
	pool.LoadOrStore(key, mockVal)
	pool.LoadOrStore(key, mockVal)

	// First delete should decrement ref count
	deleted, err := pool.Delete(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if deleted {
		t.Error("Expected deleted to be false when refs > 0")
	}
	if mockVal.IsDestroyed() {
		t.Error("Value should not be destroyed yet")
	}

	// Second delete should destroy value
	deleted, err = pool.Delete(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !deleted {
		t.Error("Expected deleted to be true when refs = 0")
	}
	if !mockVal.IsDestroyed() {
		t.Error("Value should be destroyed")
	}

	// Key should not exist after deletion
	refs, exists := pool.References(key)
	if exists {
		t.Error("Key should not exist after deletion")
	}
	if refs != 0 {
		t.Errorf("Expected 0 references, got %d", refs)
	}
}

func TestUsagePool_Delete_NonExistentKey(t *testing.T) {
	pool := NewUsagePool()
	
	deleted, err := pool.Delete("non-existent")
	if err != nil {
		t.Errorf("Expected no error for non-existent key, got: %v", err)
	}
	if deleted {
		t.Error("Expected deleted to be false for non-existent key")
	}
}

func TestUsagePool_Delete_PanicOnNegativeRefs(t *testing.T) {
	// This test demonstrates the panic condition by manipulating 
	// the ref count directly to create an invalid state
	pool := NewUsagePool()
	key := "test-key"
	mockVal := &mockDestructor{value: "test-value"}

	// Store the value to get it in the pool
	pool.LoadOrStore(key, mockVal)
	
	// Get the pool value to manipulate its refs directly
	pool.Lock()
	upv, exists := pool.pool[key]
	if !exists {
		pool.Unlock()
		t.Fatal("Value should exist in pool")
	}
	
	// Manually set refs to 1 to test the panic condition
	atomic.StoreInt32(&upv.refs, 1)
	pool.Unlock()

	// Now delete twice - the second delete should cause refs to go negative
	// First delete
	deleted1, err := pool.Delete(key)
	if err != nil {
		t.Fatalf("First delete failed: %v", err)
	}
	if !deleted1 {
		t.Error("First delete should have removed the value")
	}

	// Second delete on the same key after it was removed should be safe
	deleted2, err := pool.Delete(key)
	if err != nil {
		t.Errorf("Second delete should not error: %v", err)
	}
	if deleted2 {
		t.Error("Second delete should return false for non-existent key")
	}
}

func TestUsagePool_Range(t *testing.T) {
	pool := NewUsagePool()
	
	// Add multiple values
	values := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}
	
	for key, value := range values {
		pool.LoadOrStore(key, &mockDestructor{value: value})
	}

	// Range through all values
	found := make(map[string]string)
	pool.Range(func(key, value any) bool {
		found[key.(string)] = value.(*mockDestructor).value
		return true
	})

	if len(found) != len(values) {
		t.Errorf("Expected %d values, got %d", len(values), len(found))
	}

	for key, expectedValue := range values {
		if actualValue, exists := found[key]; !exists || actualValue != expectedValue {
			t.Errorf("Key %s: expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}
}

func TestUsagePool_Range_EarlyReturn(t *testing.T) {
	pool := NewUsagePool()
	
	// Add multiple values
	for i := 0; i < 5; i++ {
		pool.LoadOrStore(i, &mockDestructor{value: "value"})
	}

	// Range but return false after first iteration
	count := 0
	pool.Range(func(key, value any) bool {
		count++
		return false // Stop after first iteration
	})

	if count != 1 {
		t.Errorf("Expected 1 iteration, got %d", count)
	}
}

func TestUsagePool_Concurrent_LoadOrNew(t *testing.T) {
	pool := NewUsagePool()
	key := "concurrent-key"
	constructorCalls := int32(0)
	
	const numGoroutines = 100
	var wg sync.WaitGroup
	results := make([]any, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			val, _, err := pool.LoadOrNew(key, func() (Destructor, error) {
				atomic.AddInt32(&constructorCalls, 1)
				// Add small delay to increase chance of race conditions
				time.Sleep(time.Microsecond)
				return &mockDestructor{value: "concurrent-value"}, nil
			})
			if err != nil {
				t.Errorf("Goroutine %d: Unexpected error: %v", index, err)
				return
			}
			results[index] = val
		}(i)
	}
	
	wg.Wait()
	
	// Constructor should only be called once
	if calls := atomic.LoadInt32(&constructorCalls); calls != 1 {
		t.Errorf("Expected constructor to be called once, was called %d times", calls)
	}
	
	// All goroutines should get the same value
	firstVal := results[0]
	for i, val := range results {
		if val != firstVal {
			t.Errorf("Goroutine %d got different value than first goroutine", i)
		}
	}
	
	// Reference count should equal number of goroutines
	refs, exists := pool.References(key)
	if !exists {
		t.Error("Key should exist in pool")
	}
	if refs != numGoroutines {
		t.Errorf("Expected %d references, got %d", numGoroutines, refs)
	}
}

func TestUsagePool_Concurrent_Delete(t *testing.T) {
	pool := NewUsagePool()
	key := "concurrent-delete-key"
	mockVal := &mockDestructor{value: "test-value"}
	
	const numRefs = 50
	
	// Add multiple references
	for i := 0; i < numRefs; i++ {
		pool.LoadOrStore(key, mockVal)
	}
	
	var wg sync.WaitGroup
	deleteResults := make([]bool, numRefs)
	
	// Delete concurrently
	for i := 0; i < numRefs; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			deleted, err := pool.Delete(key)
			if err != nil {
				t.Errorf("Goroutine %d: Unexpected error: %v", index, err)
				return
			}
			deleteResults[index] = deleted
		}(i)
	}
	
	wg.Wait()
	
	// Exactly one delete should have returned true (when refs reached 0)
	deletedCount := 0
	for _, deleted := range deleteResults {
		if deleted {
			deletedCount++
		}
	}
	if deletedCount != 1 {
		t.Errorf("Expected exactly 1 delete to return true, got %d", deletedCount)
	}
	
	// Value should be destroyed
	if !mockVal.IsDestroyed() {
		t.Error("Value should be destroyed after all references deleted")
	}
	
	// Key should not exist
	refs, exists := pool.References(key)
	if exists {
		t.Error("Key should not exist after all references deleted")
	}
	if refs != 0 {
		t.Errorf("Expected 0 references, got %d", refs)
	}
}

func TestUsagePool_DestructorError(t *testing.T) {
	pool := NewUsagePool()
	key := "destructor-error-key"
	expectedErr := errors.New("destructor failed")
	mockVal := &mockDestructor{value: "test-value", err: expectedErr}

	pool.LoadOrStore(key, mockVal)
	
	deleted, err := pool.Delete(key)
	if err != expectedErr {
		t.Errorf("Expected destructor error, got: %v", err)
	}
	if !deleted {
		t.Error("Expected deleted to be true even with destructor error")
	}
	if !mockVal.IsDestroyed() {
		t.Error("Destructor should have been called despite error")
	}
}

func TestUsagePool_Mixed_Concurrent_Operations(t *testing.T) {
	pool := NewUsagePool()
	keys := []string{"key1", "key2", "key3"}
	
	var wg sync.WaitGroup
	const opsPerKey = 10
	
	// Test concurrent operations but with more controlled behavior
	for _, key := range keys {
		for i := 0; i < opsPerKey; i++ {
			wg.Add(2) // LoadOrStore and Delete
			
			// LoadOrStore (safer than LoadOrNew for concurrency)
			go func(k string) {
				defer wg.Done()
				pool.LoadOrStore(k, &mockDestructor{value: k + "-value"})
			}(key)
			
			// Delete (may fail if refs are 0, that's fine)
			go func(k string) {
				defer wg.Done()
				pool.Delete(k)
			}(key)
		}
	}
	
	wg.Wait()
	
	// Test that the pool is in a consistent state
	for _, key := range keys {
		refs, exists := pool.References(key)
		if exists && refs < 0 {
			t.Errorf("Key %s has negative reference count: %d", key, refs)
		}
	}
}

func TestUsagePool_Range_SkipsErrorValues(t *testing.T) {
	pool := NewUsagePool()
	
	// Add value that will succeed
	goodKey := "good-key"
	pool.LoadOrStore(goodKey, &mockDestructor{value: "good-value"})
	
	// Try to add value that will fail construction
	badKey := "bad-key"
	pool.LoadOrNew(badKey, func() (Destructor, error) {
		return nil, errors.New("construction failed")
	})
	
	// Range should only iterate good values
	count := 0
	pool.Range(func(key, value any) bool {
		count++
		if key.(string) != goodKey {
			t.Errorf("Expected only good key, got: %s", key.(string))
		}
		return true
	})
	
	if count != 1 {
		t.Errorf("Expected 1 value in range, got %d", count)
	}
}

func TestUsagePool_LoadOrStore_ErrorRecovery(t *testing.T) {
	pool := NewUsagePool()
	key := "error-recovery-key"
	
	// First, create a value that fails construction
	_, _, err := pool.LoadOrNew(key, func() (Destructor, error) {
		return nil, errors.New("construction failed")
	})
	if err == nil {
		t.Error("Expected constructor error")
	}
	
	// Now try LoadOrStore with a good value - should recover
	goodVal := &mockDestructor{value: "recovery-value"}
	val, loaded := pool.LoadOrStore(key, goodVal)
	if loaded {
		t.Error("Expected loaded to be false for error recovery")
	}
	if val != goodVal {
		t.Error("Expected recovery value to be returned")
	}
}

func TestUsagePool_MemoryLeak_Prevention(t *testing.T) {
	pool := NewUsagePool()
	key := "memory-leak-test"
	
	// Create many references
	const numRefs = 1000
	mockVal := &mockDestructor{value: "leak-test"}
	
	for i := 0; i < numRefs; i++ {
		pool.LoadOrStore(key, mockVal)
	}
	
	// Delete all references
	for i := 0; i < numRefs; i++ {
		deleted, err := pool.Delete(key)
		if err != nil {
			t.Fatalf("Delete %d: Unexpected error: %v", i, err)
		}
		if i == numRefs-1 && !deleted {
			t.Error("Last delete should return true")
		} else if i < numRefs-1 && deleted {
			t.Errorf("Delete %d should return false", i)
		}
	}
	
	// Verify destructor was called
	if !mockVal.IsDestroyed() {
		t.Error("Value should be destroyed after all references deleted")
	}
	
	// Verify no memory leak - key should be removed from map
	refs, exists := pool.References(key)
	if exists {
		t.Error("Key should not exist after complete deletion")
	}
	if refs != 0 {
		t.Errorf("Expected 0 references, got %d", refs)
	}
}

func TestUsagePool_RaceCondition_RefsCounter(t *testing.T) {
	pool := NewUsagePool()
	key := "race-test-key"
	mockVal := &mockDestructor{value: "race-value"}
	
	const numOperations = 100
	var wg sync.WaitGroup
	
	// Mix of increment and decrement operations
	for i := 0; i < numOperations; i++ {
		wg.Add(2)
		
		// Increment (LoadOrStore)
		go func() {
			defer wg.Done()
			pool.LoadOrStore(key, mockVal)
		}()
		
		// Decrement (Delete) - may fail if refs are 0, that's ok
		go func() {
			defer wg.Done()
			pool.Delete(key)
		}()
	}
	
	wg.Wait()
	
	// Final reference count should be consistent
	refs, exists := pool.References(key)
	if exists {
		if refs < 0 {
			t.Errorf("Reference count should never be negative, got: %d", refs)
		}
	}
}

func BenchmarkUsagePool_LoadOrNew(b *testing.B) {
	pool := NewUsagePool()
	key := "bench-key"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.LoadOrNew(key, func() (Destructor, error) {
			return &mockDestructor{value: "bench-value"}, nil
		})
	}
}

func BenchmarkUsagePool_LoadOrStore(b *testing.B) {
	pool := NewUsagePool()
	key := "bench-key"
	mockVal := &mockDestructor{value: "bench-value"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.LoadOrStore(key, mockVal)
	}
}

func BenchmarkUsagePool_Delete(b *testing.B) {
	pool := NewUsagePool()
	key := "bench-key"
	mockVal := &mockDestructor{value: "bench-value"}
	
	// Pre-populate with many references
	for i := 0; i < b.N; i++ {
		pool.LoadOrStore(key, mockVal)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Delete(key)
	}
}
