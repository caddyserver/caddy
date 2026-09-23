package encode

import "net/http"

// HasVaryValue exposes hasVaryValue for external tests in encode_test.
func HasVaryValue(hdr http.Header, target string) bool {
	return hasVaryValue(hdr, target)
}
