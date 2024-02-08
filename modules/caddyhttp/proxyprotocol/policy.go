package proxyprotocol

import (
	"errors"
	"fmt"
	"strings"

	goproxy "github.com/pires/go-proxyproto"
)

type Policy int

// as defined in: https://pkg.go.dev/github.com/pires/go-proxyproto@v0.7.0#Policy
const (
	// IGNORE address from PROXY header, but accept connection
	PolicyIGNORE Policy = iota
	// USE address from PROXY header
	PolicyUSE
	// REJECT connection when PROXY header is sent
	// Note: even though the first read on the connection returns an error if
	// a PROXY header is present, subsequent reads do not. It is the task of
	// the code using the connection to handle that case properly.
	PolicyREJECT
	// REQUIRE connection to send PROXY header, reject if not present
	// Note: even though the first read on the connection returns an error if
	// a PROXY header is not present, subsequent reads do not. It is the task
	// of the code using the connection to handle that case properly.
	PolicyREQUIRE
	// SKIP accepts a connection without requiring the PROXY header
	// Note: an example usage can be found in the SkipProxyHeaderForCIDR
	// function.
	PolicySKIP
)

var policyToGoProxyPolicy = map[Policy]goproxy.Policy{
	PolicyUSE:     goproxy.USE,
	PolicyIGNORE:  goproxy.IGNORE,
	PolicyREJECT:  goproxy.REJECT,
	PolicyREQUIRE: goproxy.REQUIRE,
	PolicySKIP:    goproxy.SKIP,
}

var policyMap = map[Policy]string{
	PolicyUSE:     "USE",
	PolicyIGNORE:  "IGNORE",
	PolicyREJECT:  "REJECT",
	PolicyREQUIRE: "REQUIRE",
	PolicySKIP:    "SKIP",
}

var policyMapRev = map[string]Policy{
	"USE":     PolicyUSE,
	"IGNORE":  PolicyIGNORE,
	"REJECT":  PolicyREJECT,
	"REQUIRE": PolicyREQUIRE,
	"SKIP":    PolicySKIP,
}

// MarshalText implements the text marshaller method.
func (x Policy) MarshalText() ([]byte, error) {
	return []byte(policyMap[x]), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *Policy) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := parsePolicy(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

func parsePolicy(name string) (Policy, error) {
	if x, ok := policyMapRev[strings.ToUpper(name)]; ok {
		return x, nil
	}
	return Policy(0), fmt.Errorf("%s is %w", name, errInvalidPolicy)
}

var errInvalidPolicy = errors.New("invalid policy")
