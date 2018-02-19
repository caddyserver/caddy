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

var (
	// PreCheckDNS checks DNS propagation before notifying ACME that
	// the DNS challenge is ready.
	PreCheckDNS preCheckDNSFunc = checkDNSPropagation
	fqdnToZone                  = map[string]string{}
)

const defaultResolvConf = "/etc/resolv.conf"

var defaultNameservers = []string{
	"google-public-dns-a.google.com:53",
	"google-public-dns-b.google.com:53",
}

var RecursiveNameservers = getNameservers(defaultResolvConf, defaultNameservers)

// DNSTimeout is used to override the default DNS timeout of 10 seconds.
var DNSTimeout = 10 * time.Second

// getNameservers attempts to get systems nameservers before falling back to the defaults
func getNameservers(path string, defaults []string) []string {
	config, err := dns.ClientConfigFromFile(path)
	if err != nil || len(config.Servers) == 0 {
		return defaults
	}

	systemNameservers := []string{}
	for _, server := range config.Servers {
		// ensure all servers have a port number
		if _, _, err := net.SplitHostPort(server); err != nil {
			systemNameservers = append(systemNameservers, net.JoinHostPort(server, "53"))
		} else {
			systemNameservers = append(systemNameservers, server)
		}
	}
	return systemNameservers
}

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
	keyAuth, err := getKeyAuthorization(chlng.Token, s.jws.privKey)
	if err != nil {
		return err
	}

	err = s.provider.Present(domain, chlng.Token, keyAuth)
	if err != nil {
		return fmt.Errorf("Error presenting token: %s", err)
	}
	defer func() {
		err := s.provider.CleanUp(domain, chlng.Token, keyAuth)
		if err != nil {
			log.Printf("Error cleaning up %s: %v ", domain, err)
		}
	}()

	fqdn, value, _ := DNS01Record(domain, keyAuth)

	logf("[INFO][%s] Checking DNS record propagation using %+v", domain, RecursiveNameservers)

	var timeout, interval time.Duration
	switch provider := s.provider.(type) {
	case ChallengeProviderTimeout:
		timeout, interval = provider.Timeout()
	default:
		timeout, interval = 60*time.Second, 2*time.Second
	}

	err = WaitFor(timeout, interval, func() (bool, error) {
		return PreCheckDNS(fqdn, value)
	})
	if err != nil {
		return err
	}

	return s.validate(s.jws, domain, chlng.URI, challenge{Resource: "challenge", Type: chlng.Type, Token: chlng.Token, KeyAuthorization: keyAuth})
}

// checkDNSPropagation checks if the expected TXT record has been propagated to all authoritative nameservers.
func checkDNSPropagation(fqdn, value string) (bool, error) {
	// Initial attempt to resolve at the recursive NS
	r, err := dnsQuery(fqdn, dns.TypeTXT, RecursiveNameservers, true)
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
		r, err := dnsQuery(fqdn, dns.TypeTXT, []string{net.JoinHostPort(ns, "53")}, false)
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

// dnsQuery will query a nameserver, iterating through the supplied servers as it retries
// The nameserver should include a port, to facilitate testing where we talk to a mock dns server.
func dnsQuery(fqdn string, rtype uint16, nameservers []string, recursive bool) (in *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, rtype)
	m.SetEdns0(4096, false)

	if !recursive {
		m.RecursionDesired = false
	}

	// Will retry the request based on the number of servers (n+1)
	for i := 1; i <= len(nameservers)+1; i++ {
		ns := nameservers[i%len(nameservers)]
		udp := &dns.Client{Net: "udp", Timeout: DNSTimeout}
		in, _, err = udp.Exchange(m, ns)

		if err == dns.ErrTruncated {
			tcp := &dns.Client{Net: "tcp", Timeout: DNSTimeout}
			// If the TCP request succeeds, the err will reset to nil
			in, _, err = tcp.Exchange(m, ns)
		}

		if err == nil {
			break
		}
	}
	return
}

// lookupNameservers returns the authoritative nameservers for the given fqdn.
func lookupNameservers(fqdn string) ([]string, error) {
	var authoritativeNss []string

	zone, err := FindZoneByFqdn(fqdn, RecursiveNameservers)
	if err != nil {
		return nil, fmt.Errorf("Could not determine the zone: %v", err)
	}

	r, err := dnsQuery(zone, dns.TypeNS, RecursiveNameservers, true)
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
	return nil, fmt.Errorf("Could not determine authoritative nameservers")
}

// FindZoneByFqdn determines the zone apex for the given fqdn by recursing up the
// domain labels until the nameserver returns a SOA record in the answer section.
func FindZoneByFqdn(fqdn string, nameservers []string) (string, error) {
	// Do we have it cached?
	if zone, ok := fqdnToZone[fqdn]; ok {
		return zone, nil
	}

	labelIndexes := dns.Split(fqdn)
	for _, index := range labelIndexes {
		domain := fqdn[index:]

		in, err := dnsQuery(domain, dns.TypeSOA, nameservers, true)
		if err != nil {
			return "", err
		}

		// Any response code other than NOERROR and NXDOMAIN is treated as error
		if in.Rcode != dns.RcodeNameError && in.Rcode != dns.RcodeSuccess {
			return "", fmt.Errorf("Unexpected response code '%s' for %s",
				dns.RcodeToString[in.Rcode], domain)
		}

		// Check if we got a SOA RR in the answer section
		if in.Rcode == dns.RcodeSuccess {

			// CNAME records cannot/should not exist at the root of a zone.
			// So we skip a domain when a CNAME is found.
			if dnsMsgContainsCNAME(in) {
				continue
			}

			for _, ans := range in.Answer {
				if soa, ok := ans.(*dns.SOA); ok {
					zone := soa.Hdr.Name
					fqdnToZone[fqdn] = zone
					return zone, nil
				}
			}
		}
	}

	return "", fmt.Errorf("Could not find the start of authority")
}

// dnsMsgContainsCNAME checks for a CNAME answer in msg
func dnsMsgContainsCNAME(msg *dns.Msg) bool {
	for _, ans := range msg.Answer {
		if _, ok := ans.(*dns.CNAME); ok {
			return true
		}
	}
	return false
}

// ClearFqdnCache clears the cache of fqdn to zone mappings. Primarily used in testing.
func ClearFqdnCache() {
	fqdnToZone = map[string]string{}
}

// ToFqdn converts the name into a fqdn appending a trailing dot.
func ToFqdn(name string) string {
	n := len(name)
	if n == 0 || name[n-1] == '.' {
		return name
	}
	return name + "."
}

// UnFqdn converts the fqdn into a name removing the trailing dot.
func UnFqdn(name string) string {
	n := len(name)
	if n != 0 && name[n-1] == '.' {
		return name[:n-1]
	}
	return name
}
