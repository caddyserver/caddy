package acme

import "time"

// ChallengeProvider enables implementing a custom challenge
// provider. Present presents the solution to a challenge available to
// be solved. CleanUp will be called by the challenge if Present ends
// in a non-error state.
type ChallengeProvider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}

// ChallengeProviderTimeout allows for implementing a
// ChallengeProvider where an unusually long timeout is required when
// waiting for an ACME challenge to be satisfied, such as when
// checking for DNS record progagation. If an implementor of a
// ChallengeProvider provides a Timeout method, then the return values
// of the Timeout method will be used when appropriate by the acme
// package. The interval value is the time between checks.
//
// The default values used for timeout and interval are 60 seconds and
// 2 seconds respectively. These are used when no Timeout method is
// defined for the ChallengeProvider.
type ChallengeProviderTimeout interface {
	ChallengeProvider
	Timeout() (timeout, interval time.Duration)
}
