package acme

import (
	"fmt"
	"log"
)

type httpChallenge struct {
	jws      *jws
	validate validateFunc
	provider ChallengeProvider
}

// HTTP01ChallengePath returns the URL path for the `http-01` challenge
func HTTP01ChallengePath(token string) string {
	return "/.well-known/acme-challenge/" + token
}

func (s *httpChallenge) Solve(chlng challenge, domain string) error {

	logf("[INFO][%s] acme: Trying to solve HTTP-01", domain)

	// Generate the Key Authorization for the challenge
	keyAuth, err := getKeyAuthorization(chlng.Token, s.jws.privKey)
	if err != nil {
		return err
	}

	err = s.provider.Present(domain, chlng.Token, keyAuth)
	if err != nil {
		return fmt.Errorf("[%s] error presenting token: %v", domain, err)
	}
	defer func() {
		err := s.provider.CleanUp(domain, chlng.Token, keyAuth)
		if err != nil {
			log.Printf("[%s] error cleaning up: %v", domain, err)
		}
	}()

	return s.validate(s.jws, domain, chlng.URI, challenge{Resource: "challenge", Type: chlng.Type, Token: chlng.Token, KeyAuthorization: keyAuth})
}
