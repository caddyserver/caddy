package dns

import (
	"crypto/sha1"
	"hash"
	"strings"
)

type saltWireFmt struct {
	Salt string `dns:"size-hex"`
}

// HashName hashes a string (label) according to RFC 5155. It returns the hashed string in uppercase.
func HashName(label string, ha uint8, iter uint16, salt string) string {
	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, err := packSaltWire(saltwire, wire)
	if err != nil {
		return ""
	}
	wire = wire[:n]
	name := make([]byte, 255)
	off, err := PackDomainName(strings.ToLower(label), name, 0, nil, false)
	if err != nil {
		return ""
	}
	name = name[:off]
	var s hash.Hash
	switch ha {
	case SHA1:
		s = sha1.New()
	default:
		return ""
	}

	// k = 0
	s.Write(name)
	s.Write(wire)
	nsec3 := s.Sum(nil)
	// k > 0
	for k := uint16(0); k < iter; k++ {
		s.Reset()
		s.Write(nsec3)
		s.Write(wire)
		nsec3 = s.Sum(nsec3[:0])
	}
	return toBase32(nsec3)
}

// Cover returns true if a name is covered by the NSEC3 record
func (rr *NSEC3) Cover(name string) bool {
	nameHash := HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	owner := strings.ToUpper(rr.Hdr.Name)
	labelIndices := Split(owner)
	if len(labelIndices) < 2 {
		return false
	}
	ownerHash := owner[:labelIndices[1]-1]
	ownerZone := owner[labelIndices[1]:]
	if !IsSubDomain(ownerZone, strings.ToUpper(name)) { // name is outside owner zone
		return false
	}

	nextHash := rr.NextDomain
	if ownerHash == nextHash { // empty interval
		return false
	}
	if ownerHash > nextHash { // end of zone
		if nameHash > ownerHash { // covered since there is nothing after ownerHash
			return true
		}
		return nameHash < nextHash // if nameHash is before beginning of zone it is covered
	}
	if nameHash < ownerHash { // nameHash is before ownerHash, not covered
		return false
	}
	return nameHash < nextHash // if nameHash is before nextHash is it covered (between ownerHash and nextHash)
}

// Match returns true if a name matches the NSEC3 record
func (rr *NSEC3) Match(name string) bool {
	nameHash := HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	owner := strings.ToUpper(rr.Hdr.Name)
	labelIndices := Split(owner)
	if len(labelIndices) < 2 {
		return false
	}
	ownerHash := owner[:labelIndices[1]-1]
	ownerZone := owner[labelIndices[1]:]
	if !IsSubDomain(ownerZone, strings.ToUpper(name)) { // name is outside owner zone
		return false
	}
	if ownerHash == nameHash {
		return true
	}
	return false
}

func packSaltWire(sw *saltWireFmt, msg []byte) (int, error) {
	off, err := packStringHex(sw.Salt, msg, 0)
	if err != nil {
		return off, err
	}
	return off, nil
}
