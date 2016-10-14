package httpserver

import (
	"fmt"
)

var (
	_ error = NonHijackerError{}
	_ error = NonFlusherError{}
	_ error = NonCloseNotifierError{}
)

// NonHijackerError is more descriptive error caused by a non hijacker
type NonHijackerError struct {
	// underlying type which doesn't implement Hijack
	Underlying interface{}
}

// Implement Error
func (h NonHijackerError) Error() string {
	return fmt.Sprintf("%T is not a hijacker", h.Underlying)
}

// NonFlusherError is more descriptive error caused by a non flusher
type NonFlusherError struct {
	// underlying type which doesn't implement Flush
	Underlying interface{}
}

// Implement Error
func (f NonFlusherError) Error() string {
	return fmt.Sprintf("%T is not a flusher", f.Underlying)
}

// NonCloseNotifierError is more descriptive error caused by a non closeNotifier
type NonCloseNotifierError struct {
	// underlying type which doesn't implement CloseNotify
	Underlying interface{}
}

// Implement Error
func (c NonCloseNotifierError) Error() string {
	return fmt.Sprintf("%T is not a closeNotifier", c.Underlying)
}
