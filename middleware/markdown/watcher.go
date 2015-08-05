package markdown

import (
	"log"
	"time"
)

const DefaultInterval = time.Second * 60

// Watch monitors the configured markdown directory for changes. It calls GenerateLinks
// when there are changes.
func Watch(md Markdown, c *Config, interval time.Duration) (stopChan chan struct{}) {
	return TickerFunc(interval, func() {
		if err := GenerateStatic(md, c); err != nil {
			log.Println(err)
		}
	})
}

// TickerFunc runs f at interval. A message to the returned channel will stop the
// executing goroutine.
func TickerFunc(interval time.Duration, f func()) chan struct{} {
	stopChan := make(chan struct{})

	ticker := time.NewTicker(interval)
	go func() {
	loop:
		for {
			select {
			case <-ticker.C:
				f()
			case <-stopChan:
				ticker.Stop()
				break loop
			}
		}
	}()

	return stopChan
}
