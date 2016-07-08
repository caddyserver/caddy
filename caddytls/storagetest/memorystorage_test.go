package storagetest

import "testing"

func TestMemoryStorage(t *testing.T) {
	storage := NewInMemoryStorage()
	storageTest := &StorageTest{
		Storage:  storage,
		PostTest: storage.Clear,
	}
	storageTest.Test(t, false)
}
