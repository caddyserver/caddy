package wait

import (
	"fmt"
	"time"

	"github.com/xenolf/lego/log"
)

// For polls the given function 'f', once every 'interval', up to 'timeout'.
func For(timeout, interval time.Duration, f func() (bool, error)) error {
	log.Infof("Wait [timeout: %s, interval: %s]", timeout, interval)

	var lastErr string
	timeUp := time.After(timeout)
	for {
		select {
		case <-timeUp:
			return fmt.Errorf("time limit exceeded: last error: %s", lastErr)
		default:
		}

		stop, err := f()
		if stop {
			return nil
		}
		if err != nil {
			lastErr = err.Error()
		}

		time.Sleep(interval)
	}
}
