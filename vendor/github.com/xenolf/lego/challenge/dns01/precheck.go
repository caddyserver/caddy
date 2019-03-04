package dns01

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// PreCheckFunc checks DNS propagation before notifying ACME that the DNS challenge is ready.
type PreCheckFunc func(fqdn, value string) (bool, error)

// WrapPreCheckFunc wraps a PreCheckFunc in order to do extra operations before or after
// the main check, put it in a loop, etc.
type WrapPreCheckFunc func(domain, fqdn, value string, check PreCheckFunc) (bool, error)

// WrapPreCheck Allow to define checks before notifying ACME that the DNS challenge is ready.
func WrapPreCheck(wrap WrapPreCheckFunc) ChallengeOption {
	return func(chlg *Challenge) error {
		chlg.preCheck.checkFunc = wrap
		return nil
	}
}

// AddPreCheck Allow to define checks before notifying ACME that the DNS challenge is ready.
// Deprecated: use WrapPreCheck instead.
func AddPreCheck(preCheck PreCheckFunc) ChallengeOption {
	// Prevent race condition
	check := preCheck
	return func(chlg *Challenge) error {
		chlg.preCheck.checkFunc = func(_, fqdn, value string, _ PreCheckFunc) (bool, error) {
			if check == nil {
				return false, errors.New("invalid preCheck: preCheck is nil")
			}
			return check(fqdn, value)
		}
		return nil
	}
}

func DisableCompletePropagationRequirement() ChallengeOption {
	return func(chlg *Challenge) error {
		chlg.preCheck.requireCompletePropagation = false
		return nil
	}
}

type preCheck struct {
	// checks DNS propagation before notifying ACME that the DNS challenge is ready.
	checkFunc WrapPreCheckFunc
	// require the TXT record to be propagated to all authoritative name servers
	requireCompletePropagation bool
}

func newPreCheck() preCheck {
	return preCheck{
		requireCompletePropagation: true,
	}
}

func (p preCheck) call(domain, fqdn, value string) (bool, error) {
	if p.checkFunc == nil {
		return p.checkDNSPropagation(fqdn, value)
	}

	return p.checkFunc(domain, fqdn, value, p.checkDNSPropagation)
}

// checkDNSPropagation checks if the expected TXT record has been propagated to all authoritative nameservers.
func (p preCheck) checkDNSPropagation(fqdn, value string) (bool, error) {
	// Initial attempt to resolve at the recursive NS
	r, err := dnsQuery(fqdn, dns.TypeTXT, recursiveNameservers, true)
	if err != nil {
		return false, err
	}

	if !p.requireCompletePropagation {
		return true, nil
	}

	if r.Rcode == dns.RcodeSuccess {
		fqdn = updateDomainWithCName(r, fqdn)
	}

	authoritativeNss, err := lookupNameservers(fqdn)
	if err != nil {
		return false, err
	}

	return checkAuthoritativeNss(fqdn, value, authoritativeNss)
}

// checkAuthoritativeNss queries each of the given nameservers for the expected TXT record.
func checkAuthoritativeNss(fqdn, value string, nameservers []string) (bool, error) {
	for _, ns := range nameservers {
		r, err := dnsQuery(fqdn, dns.TypeTXT, []string{net.JoinHostPort(ns, "53")}, false)
		if err != nil {
			return false, err
		}

		if r.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("NS %s returned %s for %s", ns, dns.RcodeToString[r.Rcode], fqdn)
		}

		var records []string

		var found bool
		for _, rr := range r.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				record := strings.Join(txt.Txt, "")
				records = append(records, record)
				if record == value {
					found = true
					break
				}
			}
		}

		if !found {
			return false, fmt.Errorf("NS %s did not return the expected TXT record [fqdn: %s, value: %s]: %s", ns, fqdn, value, strings.Join(records, " ,"))
		}
	}

	return true, nil
}
