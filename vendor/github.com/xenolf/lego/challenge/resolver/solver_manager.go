package resolver

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/acme/api"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/challenge/dns01"
	"github.com/xenolf/lego/challenge/http01"
	"github.com/xenolf/lego/challenge/tlsalpn01"
	"github.com/xenolf/lego/log"
)

type byType []acme.Challenge

func (a byType) Len() int           { return len(a) }
func (a byType) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byType) Less(i, j int) bool { return a[i].Type < a[j].Type }

type SolverManager struct {
	core    *api.Core
	solvers map[challenge.Type]solver
}

func NewSolversManager(core *api.Core) *SolverManager {
	solvers := map[challenge.Type]solver{
		challenge.HTTP01:    http01.NewChallenge(core, validate, &http01.ProviderServer{}),
		challenge.TLSALPN01: tlsalpn01.NewChallenge(core, validate, &tlsalpn01.ProviderServer{}),
	}

	return &SolverManager{
		solvers: solvers,
		core:    core,
	}
}

// SetHTTP01Address specifies a custom interface:port to be used for HTTP based challenges.
// If this option is not used, the default port 80 and all interfaces will be used.
// To only specify a port and no interface use the ":port" notation.
//
// NOTE: This REPLACES any custom HTTP provider previously set by calling
// c.SetProvider with the default HTTP challenge provider.
func (c *SolverManager) SetHTTP01Address(iface string) error {
	host, port, err := net.SplitHostPort(iface)
	if err != nil {
		return err
	}

	if chlng, ok := c.solvers[challenge.HTTP01]; ok {
		chlng.(*http01.Challenge).SetProvider(http01.NewProviderServer(host, port))
	}

	return nil
}

// SetTLSALPN01Address specifies a custom interface:port to be used for TLS based challenges.
// If this option is not used, the default port 443 and all interfaces will be used.
// To only specify a port and no interface use the ":port" notation.
//
// NOTE: This REPLACES any custom TLS-ALPN provider previously set by calling
// c.SetProvider with the default TLS-ALPN challenge provider.
func (c *SolverManager) SetTLSALPN01Address(iface string) error {
	host, port, err := net.SplitHostPort(iface)
	if err != nil {
		return err
	}

	if chlng, ok := c.solvers[challenge.TLSALPN01]; ok {
		chlng.(*tlsalpn01.Challenge).SetProvider(tlsalpn01.NewProviderServer(host, port))
	}

	return nil
}

// SetHTTP01Provider specifies a custom provider p that can solve the given HTTP-01 challenge.
func (c *SolverManager) SetHTTP01Provider(p challenge.Provider) error {
	c.solvers[challenge.HTTP01] = http01.NewChallenge(c.core, validate, p)
	return nil
}

// SetTLSALPN01Provider specifies a custom provider p that can solve the given TLS-ALPN-01 challenge.
func (c *SolverManager) SetTLSALPN01Provider(p challenge.Provider) error {
	c.solvers[challenge.TLSALPN01] = tlsalpn01.NewChallenge(c.core, validate, p)
	return nil
}

// SetDNS01Provider specifies a custom provider p that can solve the given DNS-01 challenge.
func (c *SolverManager) SetDNS01Provider(p challenge.Provider, opts ...dns01.ChallengeOption) error {
	c.solvers[challenge.DNS01] = dns01.NewChallenge(c.core, validate, p, opts...)
	return nil
}

// Exclude explicitly removes challenges from the pool for solving.
func (c *SolverManager) Exclude(challenges []challenge.Type) {
	// Loop through all challenges and delete the requested one if found.
	for _, chlg := range challenges {
		delete(c.solvers, chlg)
	}
}

// Checks all challenges from the server in order and returns the first matching solver.
func (c *SolverManager) chooseSolver(authz acme.Authorization) solver {
	// Allow to have a deterministic challenge order
	sort.Sort(sort.Reverse(byType(authz.Challenges)))

	domain := challenge.GetTargetedDomain(authz)
	for _, chlg := range authz.Challenges {
		if solvr, ok := c.solvers[challenge.Type(chlg.Type)]; ok {
			log.Infof("[%s] acme: use %s solver", domain, chlg.Type)
			return solvr
		}
		log.Infof("[%s] acme: Could not find solver for: %s", domain, chlg.Type)
	}

	return nil
}

func validate(core *api.Core, domain string, chlg acme.Challenge) error {
	chlng, err := core.Challenges.New(chlg.URL)
	if err != nil {
		return fmt.Errorf("failed to initiate challenge: %v", err)
	}

	valid, err := checkChallengeStatus(chlng)
	if err != nil {
		return err
	}

	if valid {
		log.Infof("[%s] The server validated our request", domain)
		return nil
	}

	// After the path is sent, the ACME server will access our server.
	// Repeatedly check the server for an updated status on our request.
	for {
		authz, err := core.Authorizations.Get(chlng.AuthorizationURL)
		if err != nil {
			return err
		}

		valid, err := checkAuthorizationStatus(authz)
		if err != nil {
			return err
		}

		if valid {
			log.Infof("[%s] The server validated our request", domain)
			return nil
		}

		ra, err := strconv.Atoi(chlng.RetryAfter)
		if err != nil {
			// The ACME server MUST return a Retry-After.
			// If it doesn't, we'll just poll hard.
			// Boulder does not implement the ability to retry challenges or the Retry-After header.
			// https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md#section-82
			ra = 5
		}
		time.Sleep(time.Duration(ra) * time.Second)
	}
}

func checkChallengeStatus(chlng acme.ExtendedChallenge) (bool, error) {
	switch chlng.Status {
	case acme.StatusValid:
		return true, nil
	case acme.StatusPending, acme.StatusProcessing:
		return false, nil
	case acme.StatusInvalid:
		return false, chlng.Error
	default:
		return false, errors.New("the server returned an unexpected state")
	}
}

func checkAuthorizationStatus(authz acme.Authorization) (bool, error) {
	switch authz.Status {
	case acme.StatusValid:
		return true, nil
	case acme.StatusPending, acme.StatusProcessing:
		return false, nil
	case acme.StatusDeactivated, acme.StatusExpired, acme.StatusRevoked:
		return false, fmt.Errorf("the authorization state %s", authz.Status)
	case acme.StatusInvalid:
		for _, chlg := range authz.Challenges {
			if chlg.Status == acme.StatusInvalid && chlg.Error != nil {
				return false, chlg.Error
			}
		}
		return false, fmt.Errorf("the authorization state %s", authz.Status)
	default:
		return false, errors.New("the server returned an unexpected state")
	}
}
