// Package digest provides HTTP Digest authentication. You may use Apache style htdigest files,
// a simple map of userXrealm->MD5(user:realm:password) or your own implementation of a user
// lookup function (if perhaps you use a database).
//

package digestauth

import (
	"net/http"
	"testing"
)

func Test_simpleNonce(t *testing.T) {

	s, err := newSimpleNonce()

	if err != nil {
		t.Errorf("failed to allocated simpleNone: %v", err)
	}

	if s.Value() == "" {
		t.Error("simple nonce did not get a value")
	}
	if s.Stale() {
		t.Error("nonce started out stale")
	}
	for i := uint(1); i < 100; i++ {
		if s.Stale() {
			t.Error("simple nonce became prematurely stale")
		}
		if !s.AcceptCounter(i) {
			t.Errorf("simple nonce did not accpet counter %d", i)
		}
	}
	if s.Stale() {
		t.Error("simple nonce became stale early")
	}

	for i := uint(100); i < 130; i++ {
		_ = s.Stale()
		if !s.AcceptCounter(i) {
			t.Errorf("simple nonce did not accpet counter %d", i)
		}
	}

	if !s.Stale() {
		t.Errorf("simple nonce failed to become stale after over use: %#v", s)
	}
}

func Test_evaluateDigest(t *testing.T) {
	nonces := newSimpleNonceStore()
	nonces.Add(&simpleNonce{value: "dcd98b7102dd2f0e8b11d0f600bfb0c093", countersSeen: map[uint]bool{}})
	nonces.Add(&simpleNonce{value: "9105d0da044827ad", countersSeen: map[uint]bool{}})
	nonces.Add(&simpleNonce{value: "37c56845de9e6fe3", countersSeen: map[uint]bool{}})
	nonces.Add(&simpleNonce{value: "dd2178ce15db3a11", countersSeen: map[uint]bool{}})
	nonces.Add(&simpleNonce{value: "73af6a8738242809", countersSeen: map[uint]bool{}})

	users := NewSimpleUserStore(map[string]string{
		"Mufasa:testrealm@host.com": "939e7578ed9e3c518a452acee763bce9", // Circle Of Life
		"foo:mortal":                "3791e8e14a10b3666ba15d9e78e4b359", // bar
	})

	digester := NewDigestHandler("testrealm@host.com", nonces, nil, users)

	// Sample data from RFC
	code, msg, stale := digester.EvaluateDigest(
		map[string]string{
			"username": "Mufasa",
			"uri":      "/dir/index.html",
			"realm":    "testrealm@host.com",
			"nonce":    "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			"nc":       "00000001",
			"cnonce":   "0a4f113b",
			"qop":      "auth",
			"response": "6629fae49393a05397450978507c4ef1",
		},
		"GET")
	if code != http.StatusOK {
		t.Errorf("EvaluateDigest failed: code=%v msg=%v stale=%v", code, msg, stale)
	}

	// Credentials from RFC, issued by curl
	code, msg, stale = digester.EvaluateDigest(
		map[string]string{
			"username": "Mufasa",
			"uri":      "/img/lioness.jpg",
			"realm":    "testrealm@host.com",
			"nonce":    "9105d0da044827ad",
			"nc":       "00000001",
			"cnonce":   "MjMxOTgy",
			"qop":      "auth",
			"response": "15c49fd482012e38a720b8a05ff63920",
		},
		"GET")
	if code != http.StatusOK {
		t.Errorf("EvaluateDigest failed: code=%v msg=%v stale=%v", code, msg, stale)
	}

	digester = NewDigestHandler("mortal", nonces, nil, users)

	// MD5 auth
	code, msg, stale = digester.EvaluateDigest(
		map[string]string{
			"username": "foo",
			"uri":      "/baz",
			"realm":    "mortal",
			"nonce":    "37c56845de9e6fe3",
			"nc":       "00000001",
			"cnonce":   "MjMyMDAy",
			"qop":      "auth",
			"response": "6c6d6a0f4d13b799bc6afcc00a14bd58",
		},
		"GET")
	if code != http.StatusOK {
		t.Errorf("EvaluateDigest failed: code=%v msg=%v stale=%v", code, msg, stale)
	}

	// No qop, legacy mode
	code, msg, stale = digester.EvaluateDigest(
		map[string]string{
			"username": "foo",
			"uri":      "/baz",
			"realm":    "mortal",
			"nonce":    "dd2178ce15db3a11",
			// no qop
			"response": "a90e57e03e1e8a5d53eb48445ae0471f",
		},
		"GET")
	if code != http.StatusOK {
		t.Errorf("EvaluateDigest failed: code=%v msg=%v stale=%v", code, msg, stale)
	}

	// MD5-sess, quth
	code, msg, stale = digester.EvaluateDigest(
		map[string]string{
			"username":  "foo",
			"uri":       "/baz",
			"realm":     "mortal",
			"nonce":     "73af6a8738242809",
			"cnonce":    "MjMyMDU0",
			"nc":        "00000001",
			"qop":       "auth",
			"algorithm": "MD5-sess",
			"response":  "ad522fee3cfb51d98914ddde2b7d2c77",
		},
		"GET")
	if code != http.StatusOK {
		t.Errorf("EvaluateDigest failed: code=%v msg=%v stale=%v", code, msg, stale)
	}

	// MD5-sess, quth Replay -- should fail
	code, msg, stale = digester.EvaluateDigest(
		map[string]string{
			"username":  "foo",
			"uri":       "/baz",
			"realm":     "mortal",
			"nonce":     "73af6a8738242809",
			"cnonce":    "MjMyMDU0",
			"nc":        "00000001",
			"qop":       "auth",
			"algorithm": "MD5-sess",
			"response":  "ad522fee3cfb51d98914ddde2b7d2c77",
		},
		"GET")
	if code != http.StatusUnauthorized || !stale {
		t.Errorf("EvaluateDigest failed to detect replayed nc: code=%v msg=%v stale=%v", code, msg, stale)
	}
}
