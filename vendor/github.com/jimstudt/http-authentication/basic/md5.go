package basic

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"strings"
)

type md5Password struct {
	salt   string
	hashed string
}

// Accept valid MD5 encoded passwords
func AcceptMd5(src string) (EncodedPasswd, error) {
	if !strings.HasPrefix(src, "$apr1$") {
		return nil, nil
	}

	rest := strings.TrimPrefix(src, "$apr1$")
	mparts := strings.SplitN(rest, "$", 2)
	if len(mparts) != 2 {
		return nil, fmt.Errorf("malformed md5 password: %s", src)
	}

	salt, hashed := mparts[0], mparts[1]
	return &md5Password{salt, hashed}, nil
}

// Reject any MD5 encoded password
func RejectMd5(src string) (EncodedPasswd, error) {
	if !strings.HasPrefix(src, "$apr1$") {
		return nil, nil
	}
	return nil, fmt.Errorf("md5 password rejected: %s", src)
}

// This is the MD5 hashing function out of Apache's htpasswd program. The algorithm
// is insane, but we have to match it. Mercifully I found a PHP variant of it at
//   http://stackoverflow.com/questions/2994637/how-to-edit-htpasswd-using-php
// in an answer. That reads better than the original C, and is easy to instrument.
// We will eventually go back to the original apr_md5.c for inspiration when the
// PHP gets too weird.
// The algorithm makes more sense if you imagine the original authors in a pub,
// drinking beer and rolling dice as the fundamental design process.
func apr1Md5(password string, salt string) string {

	// start with a hash of password and salt
	initBin := md5.Sum([]byte(password + salt + password))

	// begin an initial string with hash and salt
	initText := bytes.NewBufferString(password + "$apr1$" + salt)

	// add crap to the string willy-nilly
	for i := len(password); i > 0; i -= 16 {
		lim := i
		if lim > 16 {
			lim = 16
		}
		initText.Write(initBin[0:lim])
	}

	// add more crap to the string willy-nilly
	for i := len(password); i > 0; i >>= 1 {
		if (i & 1) == 1 {
			initText.WriteByte(byte(0))
		} else {
			initText.WriteByte(password[0])
		}
	}

	// Begin our hashing in earnest using our initial string
	bin := md5.Sum(initText.Bytes())

	n := bytes.NewBuffer([]byte{})

	for i := 0; i < 1000; i++ {
		// prepare to make a new muddle
		n.Reset()

		// alternate password+crap+bin with bin+crap+password
		if (i & 1) == 1 {
			n.WriteString(password)
		} else {
			n.Write(bin[:])
		}

		// usually add the salt, but not always
		if i%3 != 0 {
			n.WriteString(salt)
		}

		// usually add the password but not always
		if i%7 != 0 {
			n.WriteString(password)
		}

		// the back half of that alternation
		if (i & 1) == 1 {
			n.Write(bin[:])
		} else {
			n.WriteString(password)
		}

		// replace bin with the md5 of this muddle
		bin = md5.Sum(n.Bytes())
	}

	// At this point we stop transliterating the PHP code and flip back to
	// reading the Apache source. The PHP uses their base64 library, but that
	// uses the wrong character set so needs to be repaired afterwards and reversed
	// and it is just really weird to read.

	result := bytes.NewBuffer([]byte{})

	// This is our own little similar-to-base64-but-not-quite filler
	fill := func(a byte, b byte, c byte) {
		v := (uint(a) << 16) + (uint(b) << 8) + uint(c) // take our 24 input bits

		for i := 0; i < 4; i++ { // and pump out a character for each 6 bits
			result.WriteByte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[v&0x3f])
			v >>= 6
		}
	}

	// The order of these indices is strange, be careful
	fill(bin[0], bin[6], bin[12])
	fill(bin[1], bin[7], bin[13])
	fill(bin[2], bin[8], bin[14])
	fill(bin[3], bin[9], bin[15])
	fill(bin[4], bin[10], bin[5]) // 5?  Yes.
	fill(0, 0, bin[11])

	resultString := string(result.Bytes()[0:22]) // we wrote two extras since we only need 22.

	return resultString
}

func (m *md5Password) MatchesPassword(pw string) bool {
	hashed := apr1Md5(pw, m.salt)
	return constantTimeEquals(hashed, m.hashed)
}
