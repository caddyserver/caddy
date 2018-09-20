package dns

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxTok = 2048 // Largest token we can return.
const maxUint16 = 1<<16 - 1

// Tokinize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (_NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces - anywhere.
const (
	// Zonefile
	zEOF = iota
	zString
	zBlank
	zQuote
	zNewline
	zRrtpe
	zOwner
	zClass
	zDirOrigin   // $ORIGIN
	zDirTTL      // $TTL
	zDirInclude  // $INCLUDE
	zDirGenerate // $GENERATE

	// Privatekey file
	zValue
	zKey

	zExpectOwnerDir      // Ownername
	zExpectOwnerBl       // Whitespace after the ownername
	zExpectAny           // Expect rrtype, ttl or class
	zExpectAnyNoClass    // Expect rrtype or ttl
	zExpectAnyNoClassBl  // The whitespace after _EXPECT_ANY_NOCLASS
	zExpectAnyNoTTL      // Expect rrtype or class
	zExpectAnyNoTTLBl    // Whitespace after _EXPECT_ANY_NOTTL
	zExpectRrtype        // Expect rrtype
	zExpectRrtypeBl      // Whitespace BEFORE rrtype
	zExpectRdata         // The first element of the rdata
	zExpectDirTTLBl      // Space after directive $TTL
	zExpectDirTTL        // Directive $TTL
	zExpectDirOriginBl   // Space after directive $ORIGIN
	zExpectDirOrigin     // Directive $ORIGIN
	zExpectDirIncludeBl  // Space after directive $INCLUDE
	zExpectDirInclude    // Directive $INCLUDE
	zExpectDirGenerate   // Directive $GENERATE
	zExpectDirGenerateBl // Space after directive $GENERATE
)

// ParseError is a parsing error. It contains the parse error and the location in the io.Reader
// where the error occurred.
type ParseError struct {
	file string
	err  string
	lex  lex
}

func (e *ParseError) Error() (s string) {
	if e.file != "" {
		s = e.file + ": "
	}
	s += "dns: " + e.err + ": " + strconv.QuoteToASCII(e.lex.token) + " at line: " +
		strconv.Itoa(e.lex.line) + ":" + strconv.Itoa(e.lex.column)
	return
}

type lex struct {
	token      string // text of the token
	tokenUpper string // uppercase text of the token
	length     int    // length of the token
	err        bool   // when true, token text has lexer error
	value      uint8  // value: zString, _BLANK, etc.
	line       int    // line in the file
	column     int    // column in the file
	torc       uint16 // type or class as parsed in the lexer, we only need to look this up in the grammar
	comment    string // any comment text seen
}

// Token holds the token that are returned when a zone file is parsed.
type Token struct {
	// The scanned resource record when error is not nil.
	RR
	// When an error occurred, this has the error specifics.
	Error *ParseError
	// A potential comment positioned after the RR and on the same line.
	Comment string
}

// ttlState describes the state necessary to fill in an omitted RR TTL
type ttlState struct {
	ttl           uint32 // ttl is the current default TTL
	isByDirective bool   // isByDirective indicates whether ttl was set by a $TTL directive
}

// NewRR reads the RR contained in the string s. Only the first RR is
// returned. If s contains no RR, return nil with no error. The class
// defaults to IN and TTL defaults to 3600. The full zone file syntax
// like $TTL, $ORIGIN, etc. is supported. All fields of the returned
// RR are set, except RR.Header().Rdlength which is set to 0.
func NewRR(s string) (RR, error) {
	if len(s) > 0 && s[len(s)-1] != '\n' { // We need a closing newline
		return ReadRR(strings.NewReader(s+"\n"), "")
	}
	return ReadRR(strings.NewReader(s), "")
}

// ReadRR reads the RR contained in q.
// See NewRR for more documentation.
func ReadRR(q io.Reader, filename string) (RR, error) {
	defttl := &ttlState{defaultTtl, false}
	r := <-parseZoneHelper(q, ".", filename, defttl, 1)
	if r == nil {
		return nil, nil
	}

	if r.Error != nil {
		return nil, r.Error
	}
	return r.RR, nil
}

// ParseZone reads a RFC 1035 style zonefile from r. It returns *Tokens on the
// returned channel, each consisting of either a parsed RR and optional comment
// or a nil RR and an error. The string file is only used
// in error reporting. The string origin is used as the initial origin, as
// if the file would start with an $ORIGIN directive.
// The directives $INCLUDE, $ORIGIN, $TTL and $GENERATE are supported.
// The channel t is closed by ParseZone when the end of r is reached.
//
// Basic usage pattern when reading from a string (z) containing the
// zone data:
//
//	for x := range dns.ParseZone(strings.NewReader(z), "", "") {
//		if x.Error != nil {
//                  // log.Println(x.Error)
//              } else {
//                  // Do something with x.RR
//              }
//	}
//
// Comments specified after an RR (and on the same line!) are returned too:
//
//	foo. IN A 10.0.0.1 ; this is a comment
//
// The text "; this is comment" is returned in Token.Comment. Comments inside the
// RR are discarded. Comments on a line by themselves are discarded too.
func ParseZone(r io.Reader, origin, file string) chan *Token {
	return parseZoneHelper(r, origin, file, nil, 10000)
}

func parseZoneHelper(r io.Reader, origin, file string, defttl *ttlState, chansize int) chan *Token {
	t := make(chan *Token, chansize)
	go parseZone(r, origin, file, defttl, t, 0)
	return t
}

func parseZone(r io.Reader, origin, f string, defttl *ttlState, t chan *Token, include int) {
	defer func() {
		if include == 0 {
			close(t)
		}
	}()
	s, cancel := scanInit(r)
	c := make(chan lex)
	// Start the lexer
	go zlexer(s, c)

	defer func() {
		cancel()
		// zlexer can send up to three tokens, the next one and possibly 2 remainders.
		// Do a non-blocking read.
		_, ok := <-c
		_, ok = <-c
		_, ok = <-c
		if !ok {
			// too bad
		}
	}()
	// 6 possible beginnings of a line, _ is a space
	// 0. zRRTYPE                              -> all omitted until the rrtype
	// 1. zOwner _ zRrtype                     -> class/ttl omitted
	// 2. zOwner _ zString _ zRrtype           -> class omitted
	// 3. zOwner _ zString _ zClass  _ zRrtype -> ttl/class
	// 4. zOwner _ zClass  _ zRrtype           -> ttl omitted
	// 5. zOwner _ zClass  _ zString _ zRrtype -> class/ttl (reversed)
	// After detecting these, we know the zRrtype so we can jump to functions
	// handling the rdata for each of these types.

	if origin != "" {
		origin = Fqdn(origin)
		if _, ok := IsDomainName(origin); !ok {
			t <- &Token{Error: &ParseError{f, "bad initial origin name", lex{}}}
			return
		}
	}

	st := zExpectOwnerDir // initial state
	var h RR_Header
	var prevName string
	for l := range c {
		// Lexer spotted an error already
		if l.err == true {
			t <- &Token{Error: &ParseError{f, l.token, l}}
			return

		}
		switch st {
		case zExpectOwnerDir:
			// We can also expect a directive, like $TTL or $ORIGIN
			if defttl != nil {
				h.Ttl = defttl.ttl
			}
			h.Class = ClassINET
			switch l.value {
			case zNewline:
				st = zExpectOwnerDir
			case zOwner:
				h.Name = l.token
				name, ok := toAbsoluteName(l.token, origin)
				if !ok {
					t <- &Token{Error: &ParseError{f, "bad owner name", l}}
					return
				}
				h.Name = name
				prevName = h.Name
				st = zExpectOwnerBl
			case zDirTTL:
				st = zExpectDirTTLBl
			case zDirOrigin:
				st = zExpectDirOriginBl
			case zDirInclude:
				st = zExpectDirIncludeBl
			case zDirGenerate:
				st = zExpectDirGenerateBl
			case zRrtpe:
				h.Name = prevName
				h.Rrtype = l.torc
				st = zExpectRdata
			case zClass:
				h.Name = prevName
				h.Class = l.torc
				st = zExpectAnyNoClassBl
			case zBlank:
				// Discard, can happen when there is nothing on the
				// line except the RR type
			case zString:
				ttl, ok := stringToTTL(l.token)
				if !ok {
					t <- &Token{Error: &ParseError{f, "not a TTL", l}}
					return
				}
				h.Ttl = ttl
				if defttl == nil || !defttl.isByDirective {
					defttl = &ttlState{ttl, false}
				}
				st = zExpectAnyNoTTLBl

			default:
				t <- &Token{Error: &ParseError{f, "syntax error at beginning", l}}
				return
			}
		case zExpectDirIncludeBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank after $INCLUDE-directive", l}}
				return
			}
			st = zExpectDirInclude
		case zExpectDirInclude:
			if l.value != zString {
				t <- &Token{Error: &ParseError{f, "expecting $INCLUDE value, not this...", l}}
				return
			}
			neworigin := origin // There may be optionally a new origin set after the filename, if not use current one
			switch l := <-c; l.value {
			case zBlank:
				l := <-c
				if l.value == zString {
					name, ok := toAbsoluteName(l.token, origin)
					if !ok {
						t <- &Token{Error: &ParseError{f, "bad origin name", l}}
						return
					}
					neworigin = name
				}
			case zNewline, zEOF:
				// Ok
			default:
				t <- &Token{Error: &ParseError{f, "garbage after $INCLUDE", l}}
				return
			}
			// Start with the new file
			includePath := l.token
			if !filepath.IsAbs(includePath) {
				includePath = filepath.Join(filepath.Dir(f), includePath)
			}
			r1, e1 := os.Open(includePath)
			if e1 != nil {
				msg := fmt.Sprintf("failed to open `%s'", l.token)
				if !filepath.IsAbs(l.token) {
					msg += fmt.Sprintf(" as `%s'", includePath)
				}
				t <- &Token{Error: &ParseError{f, msg, l}}
				return
			}
			if include+1 > 7 {
				t <- &Token{Error: &ParseError{f, "too deeply nested $INCLUDE", l}}
				return
			}
			parseZone(r1, neworigin, includePath, defttl, t, include+1)
			st = zExpectOwnerDir
		case zExpectDirTTLBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank after $TTL-directive", l}}
				return
			}
			st = zExpectDirTTL
		case zExpectDirTTL:
			if l.value != zString {
				t <- &Token{Error: &ParseError{f, "expecting $TTL value, not this...", l}}
				return
			}
			if e, _ := slurpRemainder(c, f); e != nil {
				t <- &Token{Error: e}
				return
			}
			ttl, ok := stringToTTL(l.token)
			if !ok {
				t <- &Token{Error: &ParseError{f, "expecting $TTL value, not this...", l}}
				return
			}
			defttl = &ttlState{ttl, true}
			st = zExpectOwnerDir
		case zExpectDirOriginBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank after $ORIGIN-directive", l}}
				return
			}
			st = zExpectDirOrigin
		case zExpectDirOrigin:
			if l.value != zString {
				t <- &Token{Error: &ParseError{f, "expecting $ORIGIN value, not this...", l}}
				return
			}
			if e, _ := slurpRemainder(c, f); e != nil {
				t <- &Token{Error: e}
			}
			name, ok := toAbsoluteName(l.token, origin)
			if !ok {
				t <- &Token{Error: &ParseError{f, "bad origin name", l}}
				return
			}
			origin = name
			st = zExpectOwnerDir
		case zExpectDirGenerateBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank after $GENERATE-directive", l}}
				return
			}
			st = zExpectDirGenerate
		case zExpectDirGenerate:
			if l.value != zString {
				t <- &Token{Error: &ParseError{f, "expecting $GENERATE value, not this...", l}}
				return
			}
			if errMsg := generate(l, c, t, origin); errMsg != "" {
				t <- &Token{Error: &ParseError{f, errMsg, l}}
				return
			}
			st = zExpectOwnerDir
		case zExpectOwnerBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank after owner", l}}
				return
			}
			st = zExpectAny
		case zExpectAny:
			switch l.value {
			case zRrtpe:
				if defttl == nil {
					t <- &Token{Error: &ParseError{f, "missing TTL with no previous value", l}}
					return
				}
				h.Rrtype = l.torc
				st = zExpectRdata
			case zClass:
				h.Class = l.torc
				st = zExpectAnyNoClassBl
			case zString:
				ttl, ok := stringToTTL(l.token)
				if !ok {
					t <- &Token{Error: &ParseError{f, "not a TTL", l}}
					return
				}
				h.Ttl = ttl
				if defttl == nil || !defttl.isByDirective {
					defttl = &ttlState{ttl, false}
				}
				st = zExpectAnyNoTTLBl
			default:
				t <- &Token{Error: &ParseError{f, "expecting RR type, TTL or class, not this...", l}}
				return
			}
		case zExpectAnyNoClassBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank before class", l}}
				return
			}
			st = zExpectAnyNoClass
		case zExpectAnyNoTTLBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank before TTL", l}}
				return
			}
			st = zExpectAnyNoTTL
		case zExpectAnyNoTTL:
			switch l.value {
			case zClass:
				h.Class = l.torc
				st = zExpectRrtypeBl
			case zRrtpe:
				h.Rrtype = l.torc
				st = zExpectRdata
			default:
				t <- &Token{Error: &ParseError{f, "expecting RR type or class, not this...", l}}
				return
			}
		case zExpectAnyNoClass:
			switch l.value {
			case zString:
				ttl, ok := stringToTTL(l.token)
				if !ok {
					t <- &Token{Error: &ParseError{f, "not a TTL", l}}
					return
				}
				h.Ttl = ttl
				if defttl == nil || !defttl.isByDirective {
					defttl = &ttlState{ttl, false}
				}
				st = zExpectRrtypeBl
			case zRrtpe:
				h.Rrtype = l.torc
				st = zExpectRdata
			default:
				t <- &Token{Error: &ParseError{f, "expecting RR type or TTL, not this...", l}}
				return
			}
		case zExpectRrtypeBl:
			if l.value != zBlank {
				t <- &Token{Error: &ParseError{f, "no blank before RR type", l}}
				return
			}
			st = zExpectRrtype
		case zExpectRrtype:
			if l.value != zRrtpe {
				t <- &Token{Error: &ParseError{f, "unknown RR type", l}}
				return
			}
			h.Rrtype = l.torc
			st = zExpectRdata
		case zExpectRdata:
			r, e, c1 := setRR(h, c, origin, f)
			if e != nil {
				// If e.lex is nil than we have encounter a unknown RR type
				// in that case we substitute our current lex token
				if e.lex.token == "" && e.lex.value == 0 {
					e.lex = l // Uh, dirty
				}
				t <- &Token{Error: e}
				return
			}
			t <- &Token{RR: r, Comment: c1}
			st = zExpectOwnerDir
		}
	}
	// If we get here, we and the h.Rrtype is still zero, we haven't parsed anything, this
	// is not an error, because an empty zone file is still a zone file.
}

// zlexer scans the sourcefile and returns tokens on the channel c.
func zlexer(s *scan, c chan lex) {
	var l lex
	str := make([]byte, maxTok) // Should be enough for any token
	stri := 0                   // Offset in str (0 means empty)
	com := make([]byte, maxTok) // Hold comment text
	comi := 0
	quote := false
	escape := false
	space := false
	commt := false
	rrtype := false
	owner := true
	brace := 0
	x, err := s.tokenText()
	defer close(c)
	for err == nil {
		l.column = s.position.Column
		l.line = s.position.Line
		if stri >= maxTok {
			l.token = "token length insufficient for parsing"
			l.err = true
			c <- l
			return
		}
		if comi >= maxTok {
			l.token = "comment length insufficient for parsing"
			l.err = true
			c <- l
			return
		}

		switch x {
		case ' ', '\t':
			if escape {
				escape = false
				str[stri] = x
				stri++
				break
			}
			if quote {
				// Inside quotes this is legal
				str[stri] = x
				stri++
				break
			}
			if commt {
				com[comi] = x
				comi++
				break
			}
			if stri == 0 {
				// Space directly in the beginning, handled in the grammar
			} else if owner {
				// If we have a string and its the first, make it an owner
				l.value = zOwner
				l.token = string(str[:stri])
				l.tokenUpper = strings.ToUpper(l.token)
				l.length = stri
				// escape $... start with a \ not a $, so this will work
				switch l.tokenUpper {
				case "$TTL":
					l.value = zDirTTL
				case "$ORIGIN":
					l.value = zDirOrigin
				case "$INCLUDE":
					l.value = zDirInclude
				case "$GENERATE":
					l.value = zDirGenerate
				}
				c <- l
			} else {
				l.value = zString
				l.token = string(str[:stri])
				l.tokenUpper = strings.ToUpper(l.token)
				l.length = stri
				if !rrtype {
					if t, ok := StringToType[l.tokenUpper]; ok {
						l.value = zRrtpe
						l.torc = t
						rrtype = true
					} else {
						if strings.HasPrefix(l.tokenUpper, "TYPE") {
							t, ok := typeToInt(l.token)
							if !ok {
								l.token = "unknown RR type"
								l.err = true
								c <- l
								return
							}
							l.value = zRrtpe
							rrtype = true
							l.torc = t
						}
					}
					if t, ok := StringToClass[l.tokenUpper]; ok {
						l.value = zClass
						l.torc = t
					} else {
						if strings.HasPrefix(l.tokenUpper, "CLASS") {
							t, ok := classToInt(l.token)
							if !ok {
								l.token = "unknown class"
								l.err = true
								c <- l
								return
							}
							l.value = zClass
							l.torc = t
						}
					}
				}
				c <- l
			}
			stri = 0

			if !space && !commt {
				l.value = zBlank
				l.token = " "
				l.length = 1
				c <- l
			}
			owner = false
			space = true
		case ';':
			if escape {
				escape = false
				str[stri] = x
				stri++
				break
			}
			if quote {
				// Inside quotes this is legal
				str[stri] = x
				stri++
				break
			}
			if stri > 0 {
				l.value = zString
				l.token = string(str[:stri])
				l.tokenUpper = strings.ToUpper(l.token)
				l.length = stri
				c <- l
				stri = 0
			}
			commt = true
			com[comi] = ';'
			comi++
		case '\r':
			escape = false
			if quote {
				str[stri] = x
				stri++
				break
			}
			// discard if outside of quotes
		case '\n':
			escape = false
			// Escaped newline
			if quote {
				str[stri] = x
				stri++
				break
			}
			// inside quotes this is legal
			if commt {
				// Reset a comment
				commt = false
				rrtype = false
				stri = 0
				// If not in a brace this ends the comment AND the RR
				if brace == 0 {
					owner = true
					owner = true
					l.value = zNewline
					l.token = "\n"
					l.tokenUpper = l.token
					l.length = 1
					l.comment = string(com[:comi])
					c <- l
					l.comment = ""
					comi = 0
					break
				}
				com[comi] = ' ' // convert newline to space
				comi++
				break
			}

			if brace == 0 {
				// If there is previous text, we should output it here
				if stri != 0 {
					l.value = zString
					l.token = string(str[:stri])
					l.tokenUpper = strings.ToUpper(l.token)

					l.length = stri
					if !rrtype {
						if t, ok := StringToType[l.tokenUpper]; ok {
							l.value = zRrtpe
							l.torc = t
							rrtype = true
						}
					}
					c <- l
				}
				l.value = zNewline
				l.token = "\n"
				l.tokenUpper = l.token
				l.length = 1
				c <- l
				stri = 0
				commt = false
				rrtype = false
				owner = true
				comi = 0
			}
		case '\\':
			// comments do not get escaped chars, everything is copied
			if commt {
				com[comi] = x
				comi++
				break
			}
			// something already escaped must be in string
			if escape {
				str[stri] = x
				stri++
				escape = false
				break
			}
			// something escaped outside of string gets added to string
			str[stri] = x
			stri++
			escape = true
		case '"':
			if commt {
				com[comi] = x
				comi++
				break
			}
			if escape {
				str[stri] = x
				stri++
				escape = false
				break
			}
			space = false
			// send previous gathered text and the quote
			if stri != 0 {
				l.value = zString
				l.token = string(str[:stri])
				l.tokenUpper = strings.ToUpper(l.token)
				l.length = stri

				c <- l
				stri = 0
			}

			// send quote itself as separate token
			l.value = zQuote
			l.token = "\""
			l.tokenUpper = l.token
			l.length = 1
			c <- l
			quote = !quote
		case '(', ')':
			if commt {
				com[comi] = x
				comi++
				break
			}
			if escape {
				str[stri] = x
				stri++
				escape = false
				break
			}
			if quote {
				str[stri] = x
				stri++
				break
			}
			switch x {
			case ')':
				brace--
				if brace < 0 {
					l.token = "extra closing brace"
					l.tokenUpper = l.token
					l.err = true
					c <- l
					return
				}
			case '(':
				brace++
			}
		default:
			escape = false
			if commt {
				com[comi] = x
				comi++
				break
			}
			str[stri] = x
			stri++
			space = false
		}
		x, err = s.tokenText()
	}
	if stri > 0 {
		// Send remainder
		l.token = string(str[:stri])
		l.tokenUpper = strings.ToUpper(l.token)
		l.length = stri
		l.value = zString
		c <- l
	}
	if brace != 0 {
		l.token = "unbalanced brace"
		l.tokenUpper = l.token
		l.err = true
		c <- l
	}
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	offset := 5
	if len(token) < offset+1 {
		return 0, false
	}
	class, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(class), true
}

// Extract the rr number from TYPExxx
func typeToInt(token string) (uint16, bool) {
	offset := 4
	if len(token) < offset+1 {
		return 0, false
	}
	typ, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(typ), true
}

// stringToTTL parses things like 2w, 2m, etc, and returns the time in seconds.
func stringToTTL(token string) (uint32, bool) {
	s := uint32(0)
	i := uint32(0)
	for _, c := range token {
		switch c {
		case 's', 'S':
			s += i
			i = 0
		case 'm', 'M':
			s += i * 60
			i = 0
		case 'h', 'H':
			s += i * 60 * 60
			i = 0
		case 'd', 'D':
			s += i * 60 * 60 * 24
			i = 0
		case 'w', 'W':
			s += i * 60 * 60 * 24 * 7
			i = 0
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i *= 10
			i += uint32(c) - '0'
		default:
			return 0, false
		}
	}
	return s + i, true
}

// Parse LOC records' <digits>[.<digits>][mM] into a
// mantissa exponent format. Token should contain the entire
// string (i.e. no spaces allowed)
func stringToCm(token string) (e, m uint8, ok bool) {
	if token[len(token)-1] == 'M' || token[len(token)-1] == 'm' {
		token = token[0 : len(token)-1]
	}
	s := strings.SplitN(token, ".", 2)
	var meters, cmeters, val int
	var err error
	switch len(s) {
	case 2:
		if cmeters, err = strconv.Atoi(s[1]); err != nil {
			return
		}
		fallthrough
	case 1:
		if meters, err = strconv.Atoi(s[0]); err != nil {
			return
		}
	case 0:
		// huh?
		return 0, 0, false
	}
	ok = true
	if meters > 0 {
		e = 2
		val = meters
	} else {
		e = 0
		val = cmeters
	}
	for val > 10 {
		e++
		val /= 10
	}
	if e > 9 {
		ok = false
	}
	m = uint8(val)
	return
}

func toAbsoluteName(name, origin string) (absolute string, ok bool) {
	// check for an explicit origin reference
	if name == "@" {
		// require a nonempty origin
		if origin == "" {
			return "", false
		}
		return origin, true
	}

	// require a valid domain name
	_, ok = IsDomainName(name)
	if !ok || name == "" {
		return "", false
	}

	// check if name is already absolute
	if name[len(name)-1] == '.' {
		return name, true
	}

	// require a nonempty origin
	if origin == "" {
		return "", false
	}
	return appendOrigin(name, origin), true
}

func appendOrigin(name, origin string) string {
	if origin == "." {
		return name + origin
	}
	return name + "." + origin
}

// LOC record helper function
func locCheckNorth(token string, latitude uint32) (uint32, bool) {
	switch token {
	case "n", "N":
		return LOC_EQUATOR + latitude, true
	case "s", "S":
		return LOC_EQUATOR - latitude, true
	}
	return latitude, false
}

// LOC record helper function
func locCheckEast(token string, longitude uint32) (uint32, bool) {
	switch token {
	case "e", "E":
		return LOC_EQUATOR + longitude, true
	case "w", "W":
		return LOC_EQUATOR - longitude, true
	}
	return longitude, false
}

// "Eat" the rest of the "line". Return potential comments
func slurpRemainder(c chan lex, f string) (*ParseError, string) {
	l := <-c
	com := ""
	switch l.value {
	case zBlank:
		l = <-c
		com = l.comment
		if l.value != zNewline && l.value != zEOF {
			return &ParseError{f, "garbage after rdata", l}, ""
		}
	case zNewline:
		com = l.comment
	case zEOF:
	default:
		return &ParseError{f, "garbage after rdata", l}, ""
	}
	return nil, com
}

// Parse a 64 bit-like ipv6 address: "0014:4fff:ff20:ee64"
// Used for NID and L64 record.
func stringToNodeID(l lex) (uint64, *ParseError) {
	if len(l.token) < 19 {
		return 0, &ParseError{l.token, "bad NID/L64 NodeID/Locator64", l}
	}
	// There must be three colons at fixes postitions, if not its a parse error
	if l.token[4] != ':' && l.token[9] != ':' && l.token[14] != ':' {
		return 0, &ParseError{l.token, "bad NID/L64 NodeID/Locator64", l}
	}
	s := l.token[0:4] + l.token[5:9] + l.token[10:14] + l.token[15:19]
	u, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, &ParseError{l.token, "bad NID/L64 NodeID/Locator64", l}
	}
	return u, nil
}
