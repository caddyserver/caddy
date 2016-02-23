package acme

// ChallengeProvider presents the solution to a challenge available to be solved
// CleanUp will be called by the challenge if Present ends in a non-error state.
type ChallengeProvider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}
