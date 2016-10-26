// +build go1.8

package httpserver

import (
	"errors"
	"net/http"
)

var ErrPushUnavailable = errors.New("push is unavailable (probably chained http.ResponseWriter does not implement http.Pusher)")

func (r *ResponseRecorder) Push(target string, opts *http.PushOptions) error {
	return Push(r.ResponseWriter, target, opts)
}

// Push ensures that ResponseWriter is http.Pusher and calls Push on it
func Push(w http.ResponseWriter, target string, opts *http.PushOptions) error {
	if pusher, hasPusher := w.(http.Pusher); hasPusher {
		return pusher.Push(target, opts)
	}

	return ErrPushUnavailable
}
