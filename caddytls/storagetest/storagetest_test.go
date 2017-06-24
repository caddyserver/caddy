package storagetest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mholt/caddy/caddytls"
)

// TestFileStorage tests the file storage set with the test harness in this
// package.
func TestFileStorage(t *testing.T) {
	emailCounter := 0
	storageTest := &StorageTest{
		Storage:  &caddytls.FileStorage{Path: "./testdata"}, // nameLocks isn't made here, but it's okay because the tests don't call TryLock or Unlock
		PostTest: func() { os.RemoveAll("./testdata") },
		AfterUserEmailStore: func(email string) error {
			// We need to change the dir mod time to show a
			// that certain dirs are newer.
			emailCounter++
			fp := filepath.Join("./testdata", "users", email)

			// What we will do is subtract 10 days from today and
			// then add counter * seconds to make the later
			// counters newer. We accept that this isn't exactly
			// how the file storage works because it only changes
			// timestamps on *newly seen* users, but it achieves
			// the result that the harness expects.
			chTime := time.Now().AddDate(0, 0, -10).Add(time.Duration(emailCounter) * time.Second)
			if err := os.Chtimes(fp, chTime, chTime); err != nil {
				return fmt.Errorf("Unable to change file time for %v: %v", fp, err)
			}
			return nil
		},
	}
	storageTest.Test(t, false)
}
