package locale_test

import (
	"os"
	"testing"
)

func touchFile(tb testing.TB, path string) string {
	if _, err := os.Create(path); err != nil {
		tb.Fatal(err)
	}
	return path
}
