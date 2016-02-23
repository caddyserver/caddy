package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type preCheckDNSFunc func(fqdn, value string) (bool, error)

var preCheckDNS preCheckDNSFunc = checkDNSPropagation

var recursiveNameserver = "google-public-dns-a.google.com"

// DNS01Record returns a DNS record which will fulfill the `dns-01` challenge
func DNS01Record(domain, keyAuth string) (fqdn string, value string, ttl int) {
	keyAuthShaBytes := sha256.Sum256([]byte(keyAuth))
	// base64URL encoding without padding
	keyAuthSha := base64.URLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])
	value = strings.TrimRight(keyAuthSha, "=")
	ttl = 120
	fqdn = fmt.Sprintf("_acme-challenge.%s.", domain)
	return
}

// dnsChallenge implements the dns-01 challenge according to ACME 7.5
type dnsChallenge struct {
	jws      *jws
	validate validateFunc
	provider ChallengeProvider
}

func (s *dnsChallenge) Solve(chlng challenge, domain string) error {
	logf("[INFO][%s] acme: Trying to solve DNS-01", domain)

	if s.provider == nil {
		return errors.New("No DNS Provider configured")
	}

	// Generate the Key Authorization for the challenge
	keyAuth, err := getKeyAuthorization(chlng.Token, &s.jws.privKey.PublicKey)
	if err != nil {
		return err
	}

	err = s.provider.Present(domain, chlng.Token, keyAuth)
	if err != nil {
		return fmt.Errorf("Error presenting token %s", err)
	}
	defer func() {
		err := s.provider.CleanUp(domain, chlng.Token, keyAuth)
		if err != nil {
			log.Printf("Error cleaning up %s %v ", domain, err)
		}
	}()

	fqdn, value, _ := DNS01Record(domain, keyAuth)

	logf("[INFO][%s] Checking DNS record propagation...", domain)

	err = waitFor(30, 2, func() (bool, error) {
		return preCheckDNS(fqdn, value)
	})
	if err != nil {
		return err
	}

	return s.validate(s.jws, domain, chlng.URI, challenge{Resource: "challenge", Type: chlng.Type, Token: chlng.Token, KeyAuthorization: keyAuth})
}

// checkDNSPropagation checks if the expected TXT record has been propagated to all authoritative nameservers.
func checkDNSPropagation(fqdn, value string) (bool, error) {
	// Initial attempt to resolve at the recursive NS
	r, err := dnsQuery(fqdn, dns.TypeTXT, recursiveNameserver, true)
	if err != nil {
		return false, err
	}
	if r.Rcode == dns.RcodeSuccess {
		// If we see a CNAME here then use the alias
		for _, rr := range r.Answer {
			if cn, ok := rr.(*dns.CNAME); ok {
				if cn.Hdr.Name == fqdn {
					fqdn = cn.Target
					break
				}
			}
		}
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
		r, err := dnsQuery(fqdn, dns.TypeTXT, ns, false)
		if err != nil {
			return false, err
		}

		if r.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("NS %s returned %s for %s", ns, dns.RcodeToString[r.Rcode], fqdn)
		}

		var found bool
		for _, rr := range r.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				if strings.Join(txt.Txt, "") == value {
					found = true
					break
				}
			}
		}

		if !found {
			return false, fmt.Errorf("NS %s did not return the expected TXT record", ns)
		}
	}

	return true, nil
}

// dnsQuery sends a DNS query to the given nameserver.
func dnsQuery(fqdn string, rtype uint16, nameserver string, recursive bool) (in *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, rtype)
	m.SetEdns0(4096, false)

	if !recursive {
		m.RecursionDesired = false
	}

	in, err = dns.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err == dns.ErrTruncated {
		tcp := &dns.Client{Net: "tcp"}
		in, _, err = tcp.Exchange(m, nameserver)
	}

	return
}

// lookupNameservers returns the authoritative nameservers for the given fqdn.
func lookupNameservers(fqdn string) ([]string, error) {
	var authoritativeNss []string

	r, err := dnsQuery(fqdn, dns.TypeNS, recursiveNameserver, true)
	if err != nil {
		return nil, err
	}

	for _, rr := range r.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			authoritativeNss = append(authoritativeNss, strings.ToLower(ns.Ns))
		}
	}

	if len(authoritativeNss) > 0 {
		return authoritativeNss, nil
	}

	// Strip of the left most label to get the parent domain.
	offset, _ := dns.NextLabel(fqdn, 0)
	next := fqdn[offset:]
	if dns.CountLabel(next) < 2 {
		return nil, fmt.Errorf("Could not determine authoritative nameservers")
	}

	return lookupNameservers(next)
}

// toFqdn converts the name into a fqdn appending a trailing dot.
func toFqdn(name string) string {
	n := len(name)
	if n == 0 || name[n-1] == '.' {
		return name
	}
	return name + "."
}

// unFqdn converts the fqdn into a name removing the trailing dot.
func unFqdn(name string) string {
	n := len(name)
	if n != 0 && name[n-1] == '.' {
		return name[:n-1]
	}
	return name
}

// waitFor polls the given function 'f', once every 'interval' seconds, up to 'timeout' seconds.
func waitFor(timeout, interval int, f func() (bool, error)) error {
	var lastErr string
	timeup := time.After(time.Duration(timeout) * time.Second)
	for {
		select {
		case <-timeup:
			return fmt.Errorf("Time limit exceeded. Last error: %s", lastErr)
		default:
		}

		stop, err := f()
		if stop {
			return nil
		}
		if err != nil {
			lastErr = err.Error()
		}

		time.Sleep(time.Duration(interval) * time.Second)
	}
}
