package dns

import (
	"encoding/base64"
	"net"
	"strconv"
	"strings"
)

type parserFunc struct {
	// Func defines the function that parses the tokens and returns the RR
	// or an error. The last string contains any comments in the line as
	// they returned by the lexer as well.
	Func func(h RR_Header, c *zlexer, origin string, file string) (RR, *ParseError, string)
	// Signals if the RR ending is of variable length, like TXT or records
	// that have Hexadecimal or Base64 as their last element in the Rdata. Records
	// that have a fixed ending or for instance A, AAAA, SOA and etc.
	Variable bool
}

// Parse the rdata of each rrtype.
// All data from the channel c is either zString or zBlank.
// After the rdata there may come a zBlank and then a zNewline
// or immediately a zNewline. If this is not the case we flag
// an *ParseError: garbage after rdata.
func setRR(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	parserfunc, ok := typeToparserFunc[h.Rrtype]
	if ok {
		r, e, cm := parserfunc.Func(h, c, o, f)
		if parserfunc.Variable {
			return r, e, cm
		}
		if e != nil {
			return nil, e, ""
		}
		e, cm = slurpRemainder(c, f)
		if e != nil {
			return nil, e, ""
		}
		return r, nil, cm
	}
	// RFC3957 RR (Unknown RR handling)
	return setRFC3597(h, c, o, f)
}

// A remainder of the rdata with embedded spaces, return the parsed string (sans the spaces)
// or an error
func endingToString(c *zlexer, errstr, f string) (string, *ParseError, string) {
	s := ""
	l, _ := c.Next() // zString
	for l.value != zNewline && l.value != zEOF {
		if l.err {
			return s, &ParseError{f, errstr, l}, ""
		}
		switch l.value {
		case zString:
			s += l.token
		case zBlank: // Ok
		default:
			return "", &ParseError{f, errstr, l}, ""
		}
		l, _ = c.Next()
	}
	return s, nil, l.comment
}

// A remainder of the rdata with embedded spaces, split on unquoted whitespace
// and return the parsed string slice or an error
func endingToTxtSlice(c *zlexer, errstr, f string) ([]string, *ParseError, string) {
	// Get the remaining data until we see a zNewline
	l, _ := c.Next()
	if l.err {
		return nil, &ParseError{f, errstr, l}, ""
	}

	// Build the slice
	s := make([]string, 0)
	quote := false
	empty := false
	for l.value != zNewline && l.value != zEOF {
		if l.err {
			return nil, &ParseError{f, errstr, l}, ""
		}
		switch l.value {
		case zString:
			empty = false
			if len(l.token) > 255 {
				// split up tokens that are larger than 255 into 255-chunks
				sx := []string{}
				p, i := 0, 255
				for {
					if i <= len(l.token) {
						sx = append(sx, l.token[p:i])
					} else {
						sx = append(sx, l.token[p:])
						break

					}
					p, i = p+255, i+255
				}
				s = append(s, sx...)
				break
			}

			s = append(s, l.token)
		case zBlank:
			if quote {
				// zBlank can only be seen in between txt parts.
				return nil, &ParseError{f, errstr, l}, ""
			}
		case zQuote:
			if empty && quote {
				s = append(s, "")
			}
			quote = !quote
			empty = true
		default:
			return nil, &ParseError{f, errstr, l}, ""
		}
		l, _ = c.Next()
	}
	if quote {
		return nil, &ParseError{f, errstr, l}, ""
	}
	return s, nil, l.comment
}

func setA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(A)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	rr.A = net.ParseIP(l.token)
	if rr.A == nil || l.err {
		return nil, &ParseError{f, "bad A A", l}, ""
	}
	return rr, nil, ""
}

func setAAAA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(AAAA)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	rr.AAAA = net.ParseIP(l.token)
	if rr.AAAA == nil || l.err {
		return nil, &ParseError{f, "bad AAAA AAAA", l}, ""
	}
	return rr, nil, ""
}

func setNS(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NS)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Ns = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad NS Ns", l}, ""
	}
	rr.Ns = name
	return rr, nil, ""
}

func setPTR(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(PTR)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Ptr = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad PTR Ptr", l}, ""
	}
	rr.Ptr = name
	return rr, nil, ""
}

func setNSAPPTR(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NSAPPTR)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Ptr = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad NSAP-PTR Ptr", l}, ""
	}
	rr.Ptr = name
	return rr, nil, ""
}

func setRP(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(RP)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Mbox = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	mbox, mboxOk := toAbsoluteName(l.token, o)
	if l.err || !mboxOk {
		return nil, &ParseError{f, "bad RP Mbox", l}, ""
	}
	rr.Mbox = mbox

	c.Next() // zBlank
	l, _ = c.Next()
	rr.Txt = l.token

	txt, txtOk := toAbsoluteName(l.token, o)
	if l.err || !txtOk {
		return nil, &ParseError{f, "bad RP Txt", l}, ""
	}
	rr.Txt = txt

	return rr, nil, ""
}

func setMR(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MR)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Mr = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad MR Mr", l}, ""
	}
	rr.Mr = name
	return rr, nil, ""
}

func setMB(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MB)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Mb = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad MB Mb", l}, ""
	}
	rr.Mb = name
	return rr, nil, ""
}

func setMG(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MG)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Mg = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad MG Mg", l}, ""
	}
	rr.Mg = name
	return rr, nil, ""
}

func setHINFO(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(HINFO)
	rr.Hdr = h

	chunks, e, c1 := endingToTxtSlice(c, "bad HINFO Fields", f)
	if e != nil {
		return nil, e, c1
	}

	if ln := len(chunks); ln == 0 {
		return rr, nil, ""
	} else if ln == 1 {
		// Can we split it?
		if out := strings.Fields(chunks[0]); len(out) > 1 {
			chunks = out
		} else {
			chunks = append(chunks, "")
		}
	}

	rr.Cpu = chunks[0]
	rr.Os = strings.Join(chunks[1:], " ")

	return rr, nil, ""
}

func setMINFO(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MINFO)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Rmail = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	rmail, rmailOk := toAbsoluteName(l.token, o)
	if l.err || !rmailOk {
		return nil, &ParseError{f, "bad MINFO Rmail", l}, ""
	}
	rr.Rmail = rmail

	c.Next() // zBlank
	l, _ = c.Next()
	rr.Email = l.token

	email, emailOk := toAbsoluteName(l.token, o)
	if l.err || !emailOk {
		return nil, &ParseError{f, "bad MINFO Email", l}, ""
	}
	rr.Email = email

	return rr, nil, ""
}

func setMF(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MF)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Mf = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad MF Mf", l}, ""
	}
	rr.Mf = name
	return rr, nil, ""
}

func setMD(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MD)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Md = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad MD Md", l}, ""
	}
	rr.Md = name
	return rr, nil, ""
}

func setMX(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(MX)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad MX Pref", l}, ""
	}
	rr.Preference = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Mx = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad MX Mx", l}, ""
	}
	rr.Mx = name

	return rr, nil, ""
}

func setRT(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(RT)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil {
		return nil, &ParseError{f, "bad RT Preference", l}, ""
	}
	rr.Preference = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Host = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad RT Host", l}, ""
	}
	rr.Host = name

	return rr, nil, ""
}

func setAFSDB(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(AFSDB)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad AFSDB Subtype", l}, ""
	}
	rr.Subtype = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Hostname = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad AFSDB Hostname", l}, ""
	}
	rr.Hostname = name
	return rr, nil, ""
}

func setX25(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(X25)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	if l.err {
		return nil, &ParseError{f, "bad X25 PSDNAddress", l}, ""
	}
	rr.PSDNAddress = l.token
	return rr, nil, ""
}

func setKX(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(KX)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad KX Pref", l}, ""
	}
	rr.Preference = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Exchanger = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad KX Exchanger", l}, ""
	}
	rr.Exchanger = name
	return rr, nil, ""
}

func setCNAME(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(CNAME)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Target = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad CNAME Target", l}, ""
	}
	rr.Target = name
	return rr, nil, ""
}

func setDNAME(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(DNAME)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Target = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad DNAME Target", l}, ""
	}
	rr.Target = name
	return rr, nil, ""
}

func setSOA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(SOA)
	rr.Hdr = h

	l, _ := c.Next()
	rr.Ns = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	ns, nsOk := toAbsoluteName(l.token, o)
	if l.err || !nsOk {
		return nil, &ParseError{f, "bad SOA Ns", l}, ""
	}
	rr.Ns = ns

	c.Next() // zBlank
	l, _ = c.Next()
	rr.Mbox = l.token

	mbox, mboxOk := toAbsoluteName(l.token, o)
	if l.err || !mboxOk {
		return nil, &ParseError{f, "bad SOA Mbox", l}, ""
	}
	rr.Mbox = mbox

	c.Next() // zBlank

	var (
		v  uint32
		ok bool
	)
	for i := 0; i < 5; i++ {
		l, _ = c.Next()
		if l.err {
			return nil, &ParseError{f, "bad SOA zone parameter", l}, ""
		}
		if j, e := strconv.ParseUint(l.token, 10, 32); e != nil {
			if i == 0 {
				// Serial must be a number
				return nil, &ParseError{f, "bad SOA zone parameter", l}, ""
			}
			// We allow other fields to be unitful duration strings
			if v, ok = stringToTTL(l.token); !ok {
				return nil, &ParseError{f, "bad SOA zone parameter", l}, ""

			}
		} else {
			v = uint32(j)
		}
		switch i {
		case 0:
			rr.Serial = v
			c.Next() // zBlank
		case 1:
			rr.Refresh = v
			c.Next() // zBlank
		case 2:
			rr.Retry = v
			c.Next() // zBlank
		case 3:
			rr.Expire = v
			c.Next() // zBlank
		case 4:
			rr.Minttl = v
		}
	}
	return rr, nil, ""
}

func setSRV(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(SRV)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SRV Priority", l}, ""
	}
	rr.Priority = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SRV Weight", l}, ""
	}
	rr.Weight = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SRV Port", l}, ""
	}
	rr.Port = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Target = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad SRV Target", l}, ""
	}
	rr.Target = name
	return rr, nil, ""
}

func setNAPTR(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NAPTR)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NAPTR Order", l}, ""
	}
	rr.Order = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NAPTR Preference", l}, ""
	}
	rr.Preference = uint16(i)

	// Flags
	c.Next()        // zBlank
	l, _ = c.Next() // _QUOTE
	if l.value != zQuote {
		return nil, &ParseError{f, "bad NAPTR Flags", l}, ""
	}
	l, _ = c.Next() // Either String or Quote
	if l.value == zString {
		rr.Flags = l.token
		l, _ = c.Next() // _QUOTE
		if l.value != zQuote {
			return nil, &ParseError{f, "bad NAPTR Flags", l}, ""
		}
	} else if l.value == zQuote {
		rr.Flags = ""
	} else {
		return nil, &ParseError{f, "bad NAPTR Flags", l}, ""
	}

	// Service
	c.Next()        // zBlank
	l, _ = c.Next() // _QUOTE
	if l.value != zQuote {
		return nil, &ParseError{f, "bad NAPTR Service", l}, ""
	}
	l, _ = c.Next() // Either String or Quote
	if l.value == zString {
		rr.Service = l.token
		l, _ = c.Next() // _QUOTE
		if l.value != zQuote {
			return nil, &ParseError{f, "bad NAPTR Service", l}, ""
		}
	} else if l.value == zQuote {
		rr.Service = ""
	} else {
		return nil, &ParseError{f, "bad NAPTR Service", l}, ""
	}

	// Regexp
	c.Next()        // zBlank
	l, _ = c.Next() // _QUOTE
	if l.value != zQuote {
		return nil, &ParseError{f, "bad NAPTR Regexp", l}, ""
	}
	l, _ = c.Next() // Either String or Quote
	if l.value == zString {
		rr.Regexp = l.token
		l, _ = c.Next() // _QUOTE
		if l.value != zQuote {
			return nil, &ParseError{f, "bad NAPTR Regexp", l}, ""
		}
	} else if l.value == zQuote {
		rr.Regexp = ""
	} else {
		return nil, &ParseError{f, "bad NAPTR Regexp", l}, ""
	}

	// After quote no space??
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Replacement = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad NAPTR Replacement", l}, ""
	}
	rr.Replacement = name
	return rr, nil, ""
}

func setTALINK(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(TALINK)
	rr.Hdr = h

	l, _ := c.Next()
	rr.PreviousName = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	previousName, previousNameOk := toAbsoluteName(l.token, o)
	if l.err || !previousNameOk {
		return nil, &ParseError{f, "bad TALINK PreviousName", l}, ""
	}
	rr.PreviousName = previousName

	c.Next() // zBlank
	l, _ = c.Next()
	rr.NextName = l.token

	nextName, nextNameOk := toAbsoluteName(l.token, o)
	if l.err || !nextNameOk {
		return nil, &ParseError{f, "bad TALINK NextName", l}, ""
	}
	rr.NextName = nextName

	return rr, nil, ""
}

func setLOC(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(LOC)
	rr.Hdr = h
	// Non zero defaults for LOC record, see RFC 1876, Section 3.
	rr.HorizPre = 165 // 10000
	rr.VertPre = 162  // 10
	rr.Size = 18      // 1
	ok := false

	// North
	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}
	i, e := strconv.ParseUint(l.token, 10, 32)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad LOC Latitude", l}, ""
	}
	rr.Latitude = 1000 * 60 * 60 * uint32(i)

	c.Next() // zBlank
	// Either number, 'N' or 'S'
	l, _ = c.Next()
	if rr.Latitude, ok = locCheckNorth(l.token, rr.Latitude); ok {
		goto East
	}
	i, e = strconv.ParseUint(l.token, 10, 32)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad LOC Latitude minutes", l}, ""
	}
	rr.Latitude += 1000 * 60 * uint32(i)

	c.Next() // zBlank
	l, _ = c.Next()
	if i, e := strconv.ParseFloat(l.token, 32); e != nil || l.err {
		return nil, &ParseError{f, "bad LOC Latitude seconds", l}, ""
	} else {
		rr.Latitude += uint32(1000 * i)
	}
	c.Next() // zBlank
	// Either number, 'N' or 'S'
	l, _ = c.Next()
	if rr.Latitude, ok = locCheckNorth(l.token, rr.Latitude); ok {
		goto East
	}
	// If still alive, flag an error
	return nil, &ParseError{f, "bad LOC Latitude North/South", l}, ""

East:
	// East
	c.Next() // zBlank
	l, _ = c.Next()
	if i, e := strconv.ParseUint(l.token, 10, 32); e != nil || l.err {
		return nil, &ParseError{f, "bad LOC Longitude", l}, ""
	} else {
		rr.Longitude = 1000 * 60 * 60 * uint32(i)
	}
	c.Next() // zBlank
	// Either number, 'E' or 'W'
	l, _ = c.Next()
	if rr.Longitude, ok = locCheckEast(l.token, rr.Longitude); ok {
		goto Altitude
	}
	if i, e := strconv.ParseUint(l.token, 10, 32); e != nil || l.err {
		return nil, &ParseError{f, "bad LOC Longitude minutes", l}, ""
	} else {
		rr.Longitude += 1000 * 60 * uint32(i)
	}
	c.Next() // zBlank
	l, _ = c.Next()
	if i, e := strconv.ParseFloat(l.token, 32); e != nil || l.err {
		return nil, &ParseError{f, "bad LOC Longitude seconds", l}, ""
	} else {
		rr.Longitude += uint32(1000 * i)
	}
	c.Next() // zBlank
	// Either number, 'E' or 'W'
	l, _ = c.Next()
	if rr.Longitude, ok = locCheckEast(l.token, rr.Longitude); ok {
		goto Altitude
	}
	// If still alive, flag an error
	return nil, &ParseError{f, "bad LOC Longitude East/West", l}, ""

Altitude:
	c.Next() // zBlank
	l, _ = c.Next()
	if len(l.token) == 0 || l.err {
		return nil, &ParseError{f, "bad LOC Altitude", l}, ""
	}
	if l.token[len(l.token)-1] == 'M' || l.token[len(l.token)-1] == 'm' {
		l.token = l.token[0 : len(l.token)-1]
	}
	if i, e := strconv.ParseFloat(l.token, 32); e != nil {
		return nil, &ParseError{f, "bad LOC Altitude", l}, ""
	} else {
		rr.Altitude = uint32(i*100.0 + 10000000.0 + 0.5)
	}

	// And now optionally the other values
	l, _ = c.Next()
	count := 0
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zString:
			switch count {
			case 0: // Size
				e, m, ok := stringToCm(l.token)
				if !ok {
					return nil, &ParseError{f, "bad LOC Size", l}, ""
				}
				rr.Size = e&0x0f | m<<4&0xf0
			case 1: // HorizPre
				e, m, ok := stringToCm(l.token)
				if !ok {
					return nil, &ParseError{f, "bad LOC HorizPre", l}, ""
				}
				rr.HorizPre = e&0x0f | m<<4&0xf0
			case 2: // VertPre
				e, m, ok := stringToCm(l.token)
				if !ok {
					return nil, &ParseError{f, "bad LOC VertPre", l}, ""
				}
				rr.VertPre = e&0x0f | m<<4&0xf0
			}
			count++
		case zBlank:
			// Ok
		default:
			return nil, &ParseError{f, "bad LOC Size, HorizPre or VertPre", l}, ""
		}
		l, _ = c.Next()
	}
	return rr, nil, ""
}

func setHIP(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(HIP)
	rr.Hdr = h

	// HitLength is not represented
	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad HIP PublicKeyAlgorithm", l}, ""
	}
	rr.PublicKeyAlgorithm = uint8(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if len(l.token) == 0 || l.err {
		return nil, &ParseError{f, "bad HIP Hit", l}, ""
	}
	rr.Hit = l.token // This can not contain spaces, see RFC 5205 Section 6.
	rr.HitLength = uint8(len(rr.Hit)) / 2

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if len(l.token) == 0 || l.err {
		return nil, &ParseError{f, "bad HIP PublicKey", l}, ""
	}
	rr.PublicKey = l.token // This cannot contain spaces
	rr.PublicKeyLength = uint16(base64.StdEncoding.DecodedLen(len(rr.PublicKey)))

	// RendezvousServers (if any)
	l, _ = c.Next()
	var xs []string
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zString:
			name, nameOk := toAbsoluteName(l.token, o)
			if l.err || !nameOk {
				return nil, &ParseError{f, "bad HIP RendezvousServers", l}, ""
			}
			xs = append(xs, name)
		case zBlank:
			// Ok
		default:
			return nil, &ParseError{f, "bad HIP RendezvousServers", l}, ""
		}
		l, _ = c.Next()
	}
	rr.RendezvousServers = xs
	return rr, nil, l.comment
}

func setCERT(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(CERT)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	if v, ok := StringToCertType[l.token]; ok {
		rr.Type = v
	} else if i, e := strconv.ParseUint(l.token, 10, 16); e != nil {
		return nil, &ParseError{f, "bad CERT Type", l}, ""
	} else {
		rr.Type = uint16(i)
	}
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad CERT KeyTag", l}, ""
	}
	rr.KeyTag = uint16(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if v, ok := StringToAlgorithm[l.token]; ok {
		rr.Algorithm = v
	} else if i, e := strconv.ParseUint(l.token, 10, 8); e != nil {
		return nil, &ParseError{f, "bad CERT Algorithm", l}, ""
	} else {
		rr.Algorithm = uint8(i)
	}
	s, e1, c1 := endingToString(c, "bad CERT Certificate", f)
	if e1 != nil {
		return nil, e1, c1
	}
	rr.Certificate = s
	return rr, nil, c1
}

func setOPENPGPKEY(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(OPENPGPKEY)
	rr.Hdr = h

	s, e, c1 := endingToString(c, "bad OPENPGPKEY PublicKey", f)
	if e != nil {
		return nil, e, c1
	}
	rr.PublicKey = s
	return rr, nil, c1
}

func setCSYNC(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(CSYNC)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}
	j, e := strconv.ParseUint(l.token, 10, 32)
	if e != nil {
		// Serial must be a number
		return nil, &ParseError{f, "bad CSYNC serial", l}, ""
	}
	rr.Serial = uint32(j)

	c.Next() // zBlank

	l, _ = c.Next()
	j, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil {
		// Serial must be a number
		return nil, &ParseError{f, "bad CSYNC flags", l}, ""
	}
	rr.Flags = uint16(j)

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zBlank:
			// Ok
		case zString:
			tokenUpper := strings.ToUpper(l.token)
			if k, ok = StringToType[tokenUpper]; !ok {
				if k, ok = typeToInt(l.token); !ok {
					return nil, &ParseError{f, "bad CSYNC TypeBitMap", l}, ""
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return nil, &ParseError{f, "bad CSYNC TypeBitMap", l}, ""
		}
		l, _ = c.Next()
	}
	return rr, nil, l.comment
}

func setSIG(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setRRSIG(h, c, o, f)
	if r != nil {
		return &SIG{*r.(*RRSIG)}, e, s
	}
	return nil, e, s
}

func setRRSIG(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(RRSIG)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	tokenUpper := strings.ToUpper(l.token)
	if t, ok := StringToType[tokenUpper]; !ok {
		if strings.HasPrefix(tokenUpper, "TYPE") {
			t, ok = typeToInt(l.token)
			if !ok {
				return nil, &ParseError{f, "bad RRSIG Typecovered", l}, ""
			}
			rr.TypeCovered = t
		} else {
			return nil, &ParseError{f, "bad RRSIG Typecovered", l}, ""
		}
	} else {
		rr.TypeCovered = t
	}

	c.Next() // zBlank
	l, _ = c.Next()
	i, err := strconv.ParseUint(l.token, 10, 8)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad RRSIG Algorithm", l}, ""
	}
	rr.Algorithm = uint8(i)

	c.Next() // zBlank
	l, _ = c.Next()
	i, err = strconv.ParseUint(l.token, 10, 8)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad RRSIG Labels", l}, ""
	}
	rr.Labels = uint8(i)

	c.Next() // zBlank
	l, _ = c.Next()
	i, err = strconv.ParseUint(l.token, 10, 32)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad RRSIG OrigTtl", l}, ""
	}
	rr.OrigTtl = uint32(i)

	c.Next() // zBlank
	l, _ = c.Next()
	if i, err := StringToTime(l.token); err != nil {
		// Try to see if all numeric and use it as epoch
		if i, err := strconv.ParseInt(l.token, 10, 64); err == nil {
			// TODO(miek): error out on > MAX_UINT32, same below
			rr.Expiration = uint32(i)
		} else {
			return nil, &ParseError{f, "bad RRSIG Expiration", l}, ""
		}
	} else {
		rr.Expiration = i
	}

	c.Next() // zBlank
	l, _ = c.Next()
	if i, err := StringToTime(l.token); err != nil {
		if i, err := strconv.ParseInt(l.token, 10, 64); err == nil {
			rr.Inception = uint32(i)
		} else {
			return nil, &ParseError{f, "bad RRSIG Inception", l}, ""
		}
	} else {
		rr.Inception = i
	}

	c.Next() // zBlank
	l, _ = c.Next()
	i, err = strconv.ParseUint(l.token, 10, 16)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad RRSIG KeyTag", l}, ""
	}
	rr.KeyTag = uint16(i)

	c.Next() // zBlank
	l, _ = c.Next()
	rr.SignerName = l.token
	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad RRSIG SignerName", l}, ""
	}
	rr.SignerName = name

	s, e, c1 := endingToString(c, "bad RRSIG Signature", f)
	if e != nil {
		return nil, e, c1
	}
	rr.Signature = s

	return rr, nil, c1
}

func setNSEC(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NSEC)
	rr.Hdr = h

	l, _ := c.Next()
	rr.NextDomain = l.token
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad NSEC NextDomain", l}, ""
	}
	rr.NextDomain = name

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zBlank:
			// Ok
		case zString:
			tokenUpper := strings.ToUpper(l.token)
			if k, ok = StringToType[tokenUpper]; !ok {
				if k, ok = typeToInt(l.token); !ok {
					return nil, &ParseError{f, "bad NSEC TypeBitMap", l}, ""
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return nil, &ParseError{f, "bad NSEC TypeBitMap", l}, ""
		}
		l, _ = c.Next()
	}
	return rr, nil, l.comment
}

func setNSEC3(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NSEC3)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NSEC3 Hash", l}, ""
	}
	rr.Hash = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NSEC3 Flags", l}, ""
	}
	rr.Flags = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NSEC3 Iterations", l}, ""
	}
	rr.Iterations = uint16(i)
	c.Next()
	l, _ = c.Next()
	if len(l.token) == 0 || l.err {
		return nil, &ParseError{f, "bad NSEC3 Salt", l}, ""
	}
	if l.token != "-" {
		rr.SaltLength = uint8(len(l.token)) / 2
		rr.Salt = l.token
	}

	c.Next()
	l, _ = c.Next()
	if len(l.token) == 0 || l.err {
		return nil, &ParseError{f, "bad NSEC3 NextDomain", l}, ""
	}
	rr.HashLength = 20 // Fix for NSEC3 (sha1 160 bits)
	rr.NextDomain = l.token

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zBlank:
			// Ok
		case zString:
			tokenUpper := strings.ToUpper(l.token)
			if k, ok = StringToType[tokenUpper]; !ok {
				if k, ok = typeToInt(l.token); !ok {
					return nil, &ParseError{f, "bad NSEC3 TypeBitMap", l}, ""
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return nil, &ParseError{f, "bad NSEC3 TypeBitMap", l}, ""
		}
		l, _ = c.Next()
	}
	return rr, nil, l.comment
}

func setNSEC3PARAM(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NSEC3PARAM)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NSEC3PARAM Hash", l}, ""
	}
	rr.Hash = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NSEC3PARAM Flags", l}, ""
	}
	rr.Flags = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NSEC3PARAM Iterations", l}, ""
	}
	rr.Iterations = uint16(i)
	c.Next()
	l, _ = c.Next()
	if l.token != "-" {
		rr.SaltLength = uint8(len(l.token))
		rr.Salt = l.token
	}
	return rr, nil, ""
}

func setEUI48(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(EUI48)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	if len(l.token) != 17 || l.err {
		return nil, &ParseError{f, "bad EUI48 Address", l}, ""
	}
	addr := make([]byte, 12)
	dash := 0
	for i := 0; i < 10; i += 2 {
		addr[i] = l.token[i+dash]
		addr[i+1] = l.token[i+1+dash]
		dash++
		if l.token[i+1+dash] != '-' {
			return nil, &ParseError{f, "bad EUI48 Address", l}, ""
		}
	}
	addr[10] = l.token[15]
	addr[11] = l.token[16]

	i, e := strconv.ParseUint(string(addr), 16, 48)
	if e != nil {
		return nil, &ParseError{f, "bad EUI48 Address", l}, ""
	}
	rr.Address = i
	return rr, nil, ""
}

func setEUI64(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(EUI64)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	if len(l.token) != 23 || l.err {
		return nil, &ParseError{f, "bad EUI64 Address", l}, ""
	}
	addr := make([]byte, 16)
	dash := 0
	for i := 0; i < 14; i += 2 {
		addr[i] = l.token[i+dash]
		addr[i+1] = l.token[i+1+dash]
		dash++
		if l.token[i+1+dash] != '-' {
			return nil, &ParseError{f, "bad EUI64 Address", l}, ""
		}
	}
	addr[14] = l.token[21]
	addr[15] = l.token[22]

	i, e := strconv.ParseUint(string(addr), 16, 64)
	if e != nil {
		return nil, &ParseError{f, "bad EUI68 Address", l}, ""
	}
	rr.Address = uint64(i)
	return rr, nil, ""
}

func setSSHFP(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(SSHFP)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SSHFP Algorithm", l}, ""
	}
	rr.Algorithm = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SSHFP Type", l}, ""
	}
	rr.Type = uint8(i)
	c.Next() // zBlank
	s, e1, c1 := endingToString(c, "bad SSHFP Fingerprint", f)
	if e1 != nil {
		return nil, e1, c1
	}
	rr.FingerPrint = s
	return rr, nil, ""
}

func setDNSKEYs(h RR_Header, c *zlexer, o, f, typ string) (RR, *ParseError, string) {
	rr := new(DNSKEY)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad " + typ + " Flags", l}, ""
	}
	rr.Flags = uint16(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad " + typ + " Protocol", l}, ""
	}
	rr.Protocol = uint8(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad " + typ + " Algorithm", l}, ""
	}
	rr.Algorithm = uint8(i)
	s, e1, c1 := endingToString(c, "bad "+typ+" PublicKey", f)
	if e1 != nil {
		return nil, e1, c1
	}
	rr.PublicKey = s
	return rr, nil, c1
}

func setKEY(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setDNSKEYs(h, c, o, f, "KEY")
	if r != nil {
		return &KEY{*r.(*DNSKEY)}, e, s
	}
	return nil, e, s
}

func setDNSKEY(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setDNSKEYs(h, c, o, f, "DNSKEY")
	return r, e, s
}

func setCDNSKEY(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setDNSKEYs(h, c, o, f, "CDNSKEY")
	if r != nil {
		return &CDNSKEY{*r.(*DNSKEY)}, e, s
	}
	return nil, e, s
}

func setRKEY(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(RKEY)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad RKEY Flags", l}, ""
	}
	rr.Flags = uint16(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad RKEY Protocol", l}, ""
	}
	rr.Protocol = uint8(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad RKEY Algorithm", l}, ""
	}
	rr.Algorithm = uint8(i)
	s, e1, c1 := endingToString(c, "bad RKEY PublicKey", f)
	if e1 != nil {
		return nil, e1, c1
	}
	rr.PublicKey = s
	return rr, nil, c1
}

func setEID(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(EID)
	rr.Hdr = h
	s, e, c1 := endingToString(c, "bad EID Endpoint", f)
	if e != nil {
		return nil, e, c1
	}
	rr.Endpoint = s
	return rr, nil, c1
}

func setNIMLOC(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NIMLOC)
	rr.Hdr = h
	s, e, c1 := endingToString(c, "bad NIMLOC Locator", f)
	if e != nil {
		return nil, e, c1
	}
	rr.Locator = s
	return rr, nil, c1
}

func setGPOS(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(GPOS)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	_, e := strconv.ParseFloat(l.token, 64)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad GPOS Longitude", l}, ""
	}
	rr.Longitude = l.token
	c.Next() // zBlank
	l, _ = c.Next()
	_, e = strconv.ParseFloat(l.token, 64)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad GPOS Latitude", l}, ""
	}
	rr.Latitude = l.token
	c.Next() // zBlank
	l, _ = c.Next()
	_, e = strconv.ParseFloat(l.token, 64)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad GPOS Altitude", l}, ""
	}
	rr.Altitude = l.token
	return rr, nil, ""
}

func setDSs(h RR_Header, c *zlexer, o, f, typ string) (RR, *ParseError, string) {
	rr := new(DS)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad " + typ + " KeyTag", l}, ""
	}
	rr.KeyTag = uint16(i)
	c.Next() // zBlank
	l, _ = c.Next()
	if i, e = strconv.ParseUint(l.token, 10, 8); e != nil {
		tokenUpper := strings.ToUpper(l.token)
		i, ok := StringToAlgorithm[tokenUpper]
		if !ok || l.err {
			return nil, &ParseError{f, "bad " + typ + " Algorithm", l}, ""
		}
		rr.Algorithm = i
	} else {
		rr.Algorithm = uint8(i)
	}
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad " + typ + " DigestType", l}, ""
	}
	rr.DigestType = uint8(i)
	s, e1, c1 := endingToString(c, "bad "+typ+" Digest", f)
	if e1 != nil {
		return nil, e1, c1
	}
	rr.Digest = s
	return rr, nil, c1
}

func setDS(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setDSs(h, c, o, f, "DS")
	return r, e, s
}

func setDLV(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setDSs(h, c, o, f, "DLV")
	if r != nil {
		return &DLV{*r.(*DS)}, e, s
	}
	return nil, e, s
}

func setCDS(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	r, e, s := setDSs(h, c, o, f, "CDS")
	if r != nil {
		return &CDS{*r.(*DS)}, e, s
	}
	return nil, e, s
}

func setTA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(TA)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad TA KeyTag", l}, ""
	}
	rr.KeyTag = uint16(i)
	c.Next() // zBlank
	l, _ = c.Next()
	if i, e := strconv.ParseUint(l.token, 10, 8); e != nil {
		tokenUpper := strings.ToUpper(l.token)
		i, ok := StringToAlgorithm[tokenUpper]
		if !ok || l.err {
			return nil, &ParseError{f, "bad TA Algorithm", l}, ""
		}
		rr.Algorithm = i
	} else {
		rr.Algorithm = uint8(i)
	}
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad TA DigestType", l}, ""
	}
	rr.DigestType = uint8(i)
	s, err, c1 := endingToString(c, "bad TA Digest", f)
	if err != nil {
		return nil, err, c1
	}
	rr.Digest = s
	return rr, nil, c1
}

func setTLSA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(TLSA)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad TLSA Usage", l}, ""
	}
	rr.Usage = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad TLSA Selector", l}, ""
	}
	rr.Selector = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad TLSA MatchingType", l}, ""
	}
	rr.MatchingType = uint8(i)
	// So this needs be e2 (i.e. different than e), because...??t
	s, e2, c1 := endingToString(c, "bad TLSA Certificate", f)
	if e2 != nil {
		return nil, e2, c1
	}
	rr.Certificate = s
	return rr, nil, c1
}

func setSMIMEA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(SMIMEA)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SMIMEA Usage", l}, ""
	}
	rr.Usage = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SMIMEA Selector", l}, ""
	}
	rr.Selector = uint8(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad SMIMEA MatchingType", l}, ""
	}
	rr.MatchingType = uint8(i)
	// So this needs be e2 (i.e. different than e), because...??t
	s, e2, c1 := endingToString(c, "bad SMIMEA Certificate", f)
	if e2 != nil {
		return nil, e2, c1
	}
	rr.Certificate = s
	return rr, nil, c1
}

func setRFC3597(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(RFC3597)
	rr.Hdr = h

	l, _ := c.Next()
	if l.token != "\\#" {
		return nil, &ParseError{f, "bad RFC3597 Rdata", l}, ""
	}

	c.Next() // zBlank
	l, _ = c.Next()
	rdlength, e := strconv.Atoi(l.token)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad RFC3597 Rdata ", l}, ""
	}

	s, e1, c1 := endingToString(c, "bad RFC3597 Rdata", f)
	if e1 != nil {
		return nil, e1, c1
	}
	if rdlength*2 != len(s) {
		return nil, &ParseError{f, "bad RFC3597 Rdata", l}, ""
	}
	rr.Rdata = s
	return rr, nil, c1
}

func setSPF(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(SPF)
	rr.Hdr = h

	s, e, c1 := endingToTxtSlice(c, "bad SPF Txt", f)
	if e != nil {
		return nil, e, ""
	}
	rr.Txt = s
	return rr, nil, c1
}

func setAVC(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(AVC)
	rr.Hdr = h

	s, e, c1 := endingToTxtSlice(c, "bad AVC Txt", f)
	if e != nil {
		return nil, e, ""
	}
	rr.Txt = s
	return rr, nil, c1
}

func setTXT(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(TXT)
	rr.Hdr = h

	// no zBlank reading here, because all this rdata is TXT
	s, e, c1 := endingToTxtSlice(c, "bad TXT Txt", f)
	if e != nil {
		return nil, e, ""
	}
	rr.Txt = s
	return rr, nil, c1
}

// identical to setTXT
func setNINFO(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NINFO)
	rr.Hdr = h

	s, e, c1 := endingToTxtSlice(c, "bad NINFO ZSData", f)
	if e != nil {
		return nil, e, ""
	}
	rr.ZSData = s
	return rr, nil, c1
}

func setURI(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(URI)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad URI Priority", l}, ""
	}
	rr.Priority = uint16(i)
	c.Next() // zBlank
	l, _ = c.Next()
	i, e = strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad URI Weight", l}, ""
	}
	rr.Weight = uint16(i)

	c.Next() // zBlank
	s, err, c1 := endingToTxtSlice(c, "bad URI Target", f)
	if err != nil {
		return nil, err, ""
	}
	if len(s) != 1 {
		return nil, &ParseError{f, "bad URI Target", l}, ""
	}
	rr.Target = s[0]
	return rr, nil, c1
}

func setDHCID(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	// awesome record to parse!
	rr := new(DHCID)
	rr.Hdr = h

	s, e, c1 := endingToString(c, "bad DHCID Digest", f)
	if e != nil {
		return nil, e, c1
	}
	rr.Digest = s
	return rr, nil, c1
}

func setNID(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(NID)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad NID Preference", l}, ""
	}
	rr.Preference = uint16(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	u, err := stringToNodeID(l)
	if err != nil || l.err {
		return nil, err, ""
	}
	rr.NodeID = u
	return rr, nil, ""
}

func setL32(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(L32)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad L32 Preference", l}, ""
	}
	rr.Preference = uint16(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Locator32 = net.ParseIP(l.token)
	if rr.Locator32 == nil || l.err {
		return nil, &ParseError{f, "bad L32 Locator", l}, ""
	}
	return rr, nil, ""
}

func setLP(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(LP)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad LP Preference", l}, ""
	}
	rr.Preference = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Fqdn = l.token
	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return nil, &ParseError{f, "bad LP Fqdn", l}, ""
	}
	rr.Fqdn = name

	return rr, nil, ""
}

func setL64(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(L64)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad L64 Preference", l}, ""
	}
	rr.Preference = uint16(i)
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	u, err := stringToNodeID(l)
	if err != nil || l.err {
		return nil, err, ""
	}
	rr.Locator64 = u
	return rr, nil, ""
}

func setUID(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(UID)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 32)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad UID Uid", l}, ""
	}
	rr.Uid = uint32(i)
	return rr, nil, ""
}

func setGID(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(GID)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 32)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad GID Gid", l}, ""
	}
	rr.Gid = uint32(i)
	return rr, nil, ""
}

func setUINFO(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(UINFO)
	rr.Hdr = h

	s, e, c1 := endingToTxtSlice(c, "bad UINFO Uinfo", f)
	if e != nil {
		return nil, e, c1
	}
	if ln := len(s); ln == 0 {
		return rr, nil, c1
	}
	rr.Uinfo = s[0] // silently discard anything after the first character-string
	return rr, nil, c1
}

func setPX(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(PX)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, ""
	}

	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return nil, &ParseError{f, "bad PX Preference", l}, ""
	}
	rr.Preference = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Map822 = l.token
	map822, map822Ok := toAbsoluteName(l.token, o)
	if l.err || !map822Ok {
		return nil, &ParseError{f, "bad PX Map822", l}, ""
	}
	rr.Map822 = map822

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Mapx400 = l.token
	mapx400, mapx400Ok := toAbsoluteName(l.token, o)
	if l.err || !mapx400Ok {
		return nil, &ParseError{f, "bad PX Mapx400", l}, ""
	}
	rr.Mapx400 = mapx400

	return rr, nil, ""
}

func setCAA(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(CAA)
	rr.Hdr = h

	l, _ := c.Next()
	if len(l.token) == 0 { // dynamic update rr.
		return rr, nil, l.comment
	}

	i, err := strconv.ParseUint(l.token, 10, 8)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad CAA Flag", l}, ""
	}
	rr.Flag = uint8(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if l.value != zString {
		return nil, &ParseError{f, "bad CAA Tag", l}, ""
	}
	rr.Tag = l.token

	c.Next() // zBlank
	s, e, c1 := endingToTxtSlice(c, "bad CAA Value", f)
	if e != nil {
		return nil, e, ""
	}
	if len(s) != 1 {
		return nil, &ParseError{f, "bad CAA Value", l}, ""
	}
	rr.Value = s[0]
	return rr, nil, c1
}

func setTKEY(h RR_Header, c *zlexer, o, f string) (RR, *ParseError, string) {
	rr := new(TKEY)
	rr.Hdr = h

	l, _ := c.Next()

	// Algorithm
	if l.value != zString {
		return nil, &ParseError{f, "bad TKEY algorithm", l}, ""
	}
	rr.Algorithm = l.token
	c.Next() // zBlank

	// Get the key length and key values
	l, _ = c.Next()
	i, err := strconv.ParseUint(l.token, 10, 8)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad TKEY key length", l}, ""
	}
	rr.KeySize = uint16(i)
	c.Next() // zBlank
	l, _ = c.Next()
	if l.value != zString {
		return nil, &ParseError{f, "bad TKEY key", l}, ""
	}
	rr.Key = l.token
	c.Next() // zBlank

	// Get the otherdata length and string data
	l, _ = c.Next()
	i, err = strconv.ParseUint(l.token, 10, 8)
	if err != nil || l.err {
		return nil, &ParseError{f, "bad TKEY otherdata length", l}, ""
	}
	rr.OtherLen = uint16(i)
	c.Next() // zBlank
	l, _ = c.Next()
	if l.value != zString {
		return nil, &ParseError{f, "bad TKEY otherday", l}, ""
	}
	rr.OtherData = l.token

	return rr, nil, ""
}

var typeToparserFunc = map[uint16]parserFunc{
	TypeAAAA:       {setAAAA, false},
	TypeAFSDB:      {setAFSDB, false},
	TypeA:          {setA, false},
	TypeCAA:        {setCAA, true},
	TypeCDS:        {setCDS, true},
	TypeCDNSKEY:    {setCDNSKEY, true},
	TypeCERT:       {setCERT, true},
	TypeCNAME:      {setCNAME, false},
	TypeCSYNC:      {setCSYNC, true},
	TypeDHCID:      {setDHCID, true},
	TypeDLV:        {setDLV, true},
	TypeDNAME:      {setDNAME, false},
	TypeKEY:        {setKEY, true},
	TypeDNSKEY:     {setDNSKEY, true},
	TypeDS:         {setDS, true},
	TypeEID:        {setEID, true},
	TypeEUI48:      {setEUI48, false},
	TypeEUI64:      {setEUI64, false},
	TypeGID:        {setGID, false},
	TypeGPOS:       {setGPOS, false},
	TypeHINFO:      {setHINFO, true},
	TypeHIP:        {setHIP, true},
	TypeKX:         {setKX, false},
	TypeL32:        {setL32, false},
	TypeL64:        {setL64, false},
	TypeLOC:        {setLOC, true},
	TypeLP:         {setLP, false},
	TypeMB:         {setMB, false},
	TypeMD:         {setMD, false},
	TypeMF:         {setMF, false},
	TypeMG:         {setMG, false},
	TypeMINFO:      {setMINFO, false},
	TypeMR:         {setMR, false},
	TypeMX:         {setMX, false},
	TypeNAPTR:      {setNAPTR, false},
	TypeNID:        {setNID, false},
	TypeNIMLOC:     {setNIMLOC, true},
	TypeNINFO:      {setNINFO, true},
	TypeNSAPPTR:    {setNSAPPTR, false},
	TypeNSEC3PARAM: {setNSEC3PARAM, false},
	TypeNSEC3:      {setNSEC3, true},
	TypeNSEC:       {setNSEC, true},
	TypeNS:         {setNS, false},
	TypeOPENPGPKEY: {setOPENPGPKEY, true},
	TypePTR:        {setPTR, false},
	TypePX:         {setPX, false},
	TypeSIG:        {setSIG, true},
	TypeRKEY:       {setRKEY, true},
	TypeRP:         {setRP, false},
	TypeRRSIG:      {setRRSIG, true},
	TypeRT:         {setRT, false},
	TypeSMIMEA:     {setSMIMEA, true},
	TypeSOA:        {setSOA, false},
	TypeSPF:        {setSPF, true},
	TypeAVC:        {setAVC, true},
	TypeSRV:        {setSRV, false},
	TypeSSHFP:      {setSSHFP, true},
	TypeTALINK:     {setTALINK, false},
	TypeTA:         {setTA, true},
	TypeTLSA:       {setTLSA, true},
	TypeTXT:        {setTXT, true},
	TypeUID:        {setUID, false},
	TypeUINFO:      {setUINFO, true},
	TypeURI:        {setURI, true},
	TypeX25:        {setX25, false},
	TypeTKEY:       {setTKEY, true},
}
