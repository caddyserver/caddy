package challenge

import (
	"fmt"

	"github.com/xenolf/lego/acme"
)

// Type is a string that identifies a particular challenge type and version of ACME challenge.
type Type string

const (
	// HTTP01 is the "http-01" ACME challenge https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-8.3
	// Note: ChallengePath returns the URL path to fulfill this challenge
	HTTP01 = Type("http-01")

	// DNS01 is the "dns-01" ACME challenge https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-8.4
	// Note: GetRecord returns a DNS record which will fulfill this challenge
	DNS01 = Type("dns-01")

	// TLSALPN01 is the "tls-alpn-01" ACME challenge https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05
	TLSALPN01 = Type("tls-alpn-01")
)

func (t Type) String() string {
	return string(t)
}

func FindChallenge(chlgType Type, authz acme.Authorization) (acme.Challenge, error) {
	for _, chlg := range authz.Challenges {
		if chlg.Type == string(chlgType) {
			return chlg, nil
		}
	}

	return acme.Challenge{}, fmt.Errorf("[%s] acme: unable to find challenge %s", GetTargetedDomain(authz), chlgType)
}

func GetTargetedDomain(authz acme.Authorization) string {
	if authz.Wildcard {
		return "*." + authz.Identifier.Value
	}
	return authz.Identifier.Value
}
