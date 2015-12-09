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
	syncChan := make(chan struct{})
	stopChan := TickerFunc(interval, func() {
		i++
		out += fmt.Sprint(i)
		syncChan <- struct{}{}
	})
	sleepInSync(8, syncChan, stopChan)
	if out != expected {
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
		syncChan <- struct{}{}
	})
	sleepInSync(9, syncChan, stopChan)
	mu.Lock()
	res := out
	mu.Unlock()
	if !strings.HasPrefix(res, expected) || res == expected {
		t.Fatalf("expected (%v) must be a proper prefix of out(%v).", expected, out)
	}
}

func sleepInSync(times int, syncChan chan struct{}, stopChan chan struct{}) {
	for i := 0; i < times; i++ {
		<-syncChan
	}
	stopChan <- struct{}{}
}
