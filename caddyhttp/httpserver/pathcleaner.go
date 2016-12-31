package httpserver

import (
	"math/rand"
	"path"
	"strings"
	"time"
)

// A proxy function to prevent one or more of the path cleanup operations:
//   - collapse multiple slashes into one
//   - eliminate "/." (current directory)
//   - eliminate "<parent_directory>/.."
// by masking certain patterns in the path with a temporary random string.
// This could be helpful when certain patterns in the path are desired
// that would otherwise be changed in the path clean up process.
// One such use case is the presence of the double slashes as protocol separator
// (e.g., /api/endpoint/http://example.com).
// This is a common pattern in many applications to allow passing URIs as path argument
func CleanMaskedPath(p string, mask ...string) string {
	var t string
	maskMap := make(map[string]string)

	// Iterate over supplied masks and create temporary replacement strings
	// only for the masks that are present in the path, then replace all occurrences
	for _, m := range mask {
		if strings.Index(p, m) >= 0 {
			t = "/_caddy" + generateRandomString() + "__"
			maskMap[m] = t
			p = strings.Replace(p, m, t, -1)
		}
	}

	p = path.Clean(p)

	// Revert the replaced masks after path cleanup
	for m, t := range maskMap {
		p = strings.Replace(p, t, m, -1)
	}
	return p
}

func CleanPath(p string) string {
	// Apply the default mask to preserve double slashes of protocols
	// such as "http://", "https://", and "ftp://" etc.
	return CleanMaskedPath(p, "://")
}

// The most efficient method for random string generation.
// Inspired by http://stackoverflow.com/a/31832326.
const randomStringLenght = 10
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = rand.NewSource(time.Now().UnixNano())

func generateRandomString() string {
	b := make([]byte, randomStringLenght)
	for i, cache, remain := randomStringLenght-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}
