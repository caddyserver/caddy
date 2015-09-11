package markdown

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWatcher(t *testing.T) {
	expected := "12345678"
	interval := time.Millisecond * 100
	i := 0
	out := ""
	stopChan := TickerFunc(interval, func() {
		i++
		out += fmt.Sprint(i)
	})
	// wait little more because of concurrency
	time.Sleep(interval * 9)
	stopChan <- struct{}{}
	if !strings.HasPrefix(out, expected) {
		t.Fatalf("Expected to have prefix %v, found %v", expected, out)
	}
	out = ""
	i = 0
	var mu sync.Mutex
	stopChan = TickerFunc(interval, func() {
		i++
		mu.Lock()
		out += fmt.Sprint(i)
		mu.Unlock()
	})
	time.Sleep(interval * 10)
	mu.Lock()
	res := out
	mu.Unlock()
	if !strings.HasPrefix(res, expected) || res == expected {
		t.Fatalf("expected (%v) must be a proper prefix of out(%v).", expected, out)
	}
}
