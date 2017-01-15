package httpserver

import (
	"math/rand"
	"path"
	"strings"
	"time"
)

// CleanMaskedPath prevents one or more of the path cleanup operations:
//   - collapse multiple slashes into one
//   - eliminate "/." (current directory)
//   - eliminate "<parent_directory>/.."
// by masking certain patterns in the path with a temporary random string.
// This could be helpful when certain patterns in the path are desired to be preserved
// that would otherwise be changed by path.Clean().
// One such use case is the presence of the double slashes as protocol separator
// (e.g., /api/endpoint/http://example.com).
// This is a common pattern in many applications to allow passing URIs as path argument.
func CleanMaskedPath(reqPath string, masks ...string) string {
	var replacerVal string
	maskMap := make(map[string]string)

	// Iterate over supplied masks and create temporary replacement strings
	// only for the masks that are present in the path, then replace all occurrences
	for _, mask := range masks {
		if strings.Index(reqPath, mask) >= 0 {
			replacerVal = "/_caddy" + generateRandomString() + "__"
			maskMap[mask] = replacerVal
			reqPath = strings.Replace(reqPath, mask, replacerVal, -1)
		}
	}

	reqPath = path.Clean(reqPath)

	// Revert the replaced masks after path cleanup
	for mask, replacerVal := range maskMap {
		reqPath = strings.Replace(reqPath, replacerVal, mask, -1)
	}
	return reqPath
}

// CleanPath calls CleanMaskedPath() with the default mask of "://"
// to preserve double slashes of protocols
// such as "http://", "https://", and "ftp://" etc.
func CleanPath(reqPath string) string {
	return CleanMaskedPath(reqPath, "://")
}

// An efficient and fast method for random string generation.
// Inspired by http://stackoverflow.com/a/31832326.
const randomStringLength = 4
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = rand.NewSource(time.Now().UnixNano())

func generateRandomString() string {
	b := make([]byte, randomStringLength)
	for i, cache, remain := randomStringLength-1, src.Int63(), letterIdxMax; i >= 0; {
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
