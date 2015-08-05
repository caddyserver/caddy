package markdown

import (
	"fmt"
	"strings"
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
	time.Sleep(interval * 8)
	stopChan <- struct{}{}
	if expected != out {
		t.Fatalf("Expected %v, found %v", expected, out)
	}
	out = ""
	i = 0
	stopChan = TickerFunc(interval, func() {
		i++
		out += fmt.Sprint(i)
	})
	time.Sleep(interval * 10)
	if !strings.HasPrefix(out, expected) || out == expected {
		t.Fatalf("expected (%v) must be a proper prefix of out(%v).", expected, out)
	}
}
