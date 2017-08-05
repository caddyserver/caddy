package basic

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

type shaPassword struct {
	hashed []byte
}

// Accept valid SHA encoded passwords.
func AcceptSha(src string) (EncodedPasswd, error) {
	if !strings.HasPrefix(src, "{SHA}") {
		return nil, nil
	}

	b64 := strings.TrimPrefix(src, "{SHA}")
	hashed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("Malformed sha1(%s): %s", src, err.Error())
	}
	if len(hashed) != sha1.Size {
		return nil, fmt.Errorf("Malformed sha1(%s): wrong length", src)
	}
	return &shaPassword{hashed}, nil
}

// Reject any password encoded as SHA.
func RejectSha(src string) (EncodedPasswd, error) {
	if !strings.HasPrefix(src, "{SHA}") {
		return nil, nil
	}
	return nil, fmt.Errorf("sha password rejected: %s", src)
}

func (s *shaPassword) MatchesPassword(pw string) bool {
	h := sha1.Sum([]byte(pw))
	return subtle.ConstantTimeCompare(h[:], s.hashed) == 1
}
