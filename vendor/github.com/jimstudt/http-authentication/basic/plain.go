package basic

import (
	"fmt"
)

type plainPassword struct {
	password string
}

// Accept any password in the plain text encoding.
// Be careful: This matches any line, so it *must* be the last parser in you list.
func AcceptPlain(pw string) (EncodedPasswd, error) {
	return &plainPassword{pw}, nil
}

// Reject any plain text encoded passoword.
// Be careful: This matches any line, so it *must* be the last parser in you list.
func RejectPlain(pw string) (EncodedPasswd, error) {
	return nil, fmt.Errorf("plain password rejected: %s", pw)
}

func (p *plainPassword) MatchesPassword(pw string) bool {
	// Notice: nginx prefixes plain passwords with {PLAIN}, so we see if that would
	//         let us match too. I'd split {PLAIN} off, but someone probably uses that
	//         in their password. It's a big planet.
	return constantTimeEquals(pw, p.password) || constantTimeEquals("{PLAIN}"+pw, p.password)
}
