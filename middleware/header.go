package middleware

import (
	"net/http"
	"time"
)

// currentTime returns time.Now() everytime it's called. It's used for mocking in tests.
var currentTime = func() time.Time {
	return time.Now()
}

// SetLastModifiedHeader checks if the provided modTime is valid and if it is sets it
// as a Last-Modified header to the ResponseWriter. If the modTime is in the future
// the current time is used instead.
func SetLastModifiedHeader(w http.ResponseWriter, modTime time.Time) {
	if modTime.IsZero() || modTime.Equal(time.Unix(0, 0)) {
		// the time does not appear to be valid. Don't put it in the response
		return
	}

	// RFC 2616 - Section 14.29 - Last-Modified:
	// An origin server MUST NOT send a Last-Modified date which is later than the
	// server's time of message origination. In such cases, where the resource's last
	// modification would indicate some time in the future, the server MUST replace
	// that date with the message origination date.
	now := currentTime()
	if modTime.After(now) {
		modTime = now
	}

	w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
}
