package basic

import (
	"fmt"
	"strings"
)

// Reject any password encoded using bcrypt.
func RejectBcrypt(src string) (EncodedPasswd, error) {
	if strings.HasPrefix(src, "$2y$") {
		return nil, fmt.Errorf("bcrypt passwords are not accepted: %s", src)
	}

	return nil, nil
}
