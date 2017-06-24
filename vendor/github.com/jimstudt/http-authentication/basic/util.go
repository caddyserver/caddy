package basic

import (
	"crypto/sha1"
	"crypto/subtle"
)

func constantTimeEquals(a string, b string) bool {
	// compare SHA-1 as a gatekeeper in constant time
	// then check that we didn't get by because of a collision
	aSha := sha1.Sum([]byte(a))
	bSha := sha1.Sum([]byte(b))
	if subtle.ConstantTimeCompare(aSha[:], bSha[:]) == 1 {
		// yes, this bit isn't constant, but you had to make a Sha1 collision to get here
		return a == b
	}
	return false
}
