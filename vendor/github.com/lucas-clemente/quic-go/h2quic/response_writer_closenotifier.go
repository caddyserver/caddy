package h2quic

import "net/http"

// The CloseNotifier is a deprecated interface, and staticcheck will report that from Go 1.11.
// By defining it in a separate file, we can exclude this file from staticcheck.

// test that we implement http.CloseNotifier
var _ http.CloseNotifier = &responseWriter{}
