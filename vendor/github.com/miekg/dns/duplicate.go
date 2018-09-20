package dns

//go:generate go run duplicate_generate.go

// IsDuplicate checks of r1 and r2 are duplicates of each other, excluding the TTL.
// So this means the header data is equal *and* the RDATA is the same. Return true
// is so, otherwise false.
// It's is a protocol violation to have identical RRs in a message.
func IsDuplicate(r1, r2 RR) bool {
	if r1.Header().Class != r2.Header().Class {
		return false
	}
	if r1.Header().Rrtype != r2.Header().Rrtype {
		return false
	}
	if !isDulicateName(r1.Header().Name, r2.Header().Name) {
		return false
	}
	// ignore TTL

	return isDuplicateRdata(r1, r2)
}

// isDulicateName checks if the domain names s1 and s2 are equal.
func isDulicateName(s1, s2 string) bool { return equal(s1, s2) }
