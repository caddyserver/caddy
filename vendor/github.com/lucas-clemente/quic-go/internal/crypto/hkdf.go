package crypto

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
)

// copied from https://github.com/cloudflare/tls-tris/blob/master/hkdf.go
func hkdfExtract(hash crypto.Hash, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, hash.Size())
	}
	if secret == nil {
		secret = make([]byte, hash.Size())
	}
	extractor := hmac.New(hash.New, salt)
	extractor.Write(secret)
	return extractor.Sum(nil)
}

// copied from https://github.com/cloudflare/tls-tris/blob/master/hkdf.go
func hkdfExpand(hash crypto.Hash, prk, info []byte, l int) []byte {
	var (
		expander = hmac.New(hash.New, prk)
		res      = make([]byte, l)
		counter  = byte(1)
		prev     []byte
	)

	if l > 255*expander.Size() {
		panic("hkdf: requested too much output")
	}

	p := res
	for len(p) > 0 {
		expander.Reset()
		expander.Write(prev)
		expander.Write(info)
		expander.Write([]byte{counter})
		prev = expander.Sum(prev[:0])
		counter++
		n := copy(p, prev)
		p = p[n:]
	}

	return res
}

func qhkdfExpand(secret []byte, label string, length int) []byte {
	qlabel := make([]byte, 2+1+5+len(label))
	binary.BigEndian.PutUint16(qlabel[0:2], uint16(length))
	qlabel[2] = uint8(5 + len(label))
	copy(qlabel[3:], []byte("QUIC "+label))
	return hkdfExpand(crypto.SHA256, secret, qlabel, length)
}
