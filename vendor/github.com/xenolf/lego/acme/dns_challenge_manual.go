package acme

import (
	"bufio"
	"fmt"
	"os"

	"github.com/xenolf/lego/log"
)

const (
	dnsTemplate = "%s %d IN TXT \"%s\""
)

// DNSProviderManual is an implementation of the ChallengeProvider interface
type DNSProviderManual struct{}

// NewDNSProviderManual returns a DNSProviderManual instance.
func NewDNSProviderManual() (*DNSProviderManual, error) {
	return &DNSProviderManual{}, nil
}

// Present prints instructions for manually creating the TXT record
func (*DNSProviderManual) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := DNS01Record(domain, keyAuth)
	dnsRecord := fmt.Sprintf(dnsTemplate, fqdn, ttl, value)

	authZone, err := FindZoneByFqdn(fqdn, RecursiveNameservers)
	if err != nil {
		return err
	}

	log.Infof("acme: Please create the following TXT record in your %s zone:", authZone)
	log.Infof("acme: %s", dnsRecord)
	log.Infof("acme: Press 'Enter' when you are done")

	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
	return nil
}

// CleanUp prints instructions for manually removing the TXT record
func (*DNSProviderManual) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, ttl := DNS01Record(domain, keyAuth)
	dnsRecord := fmt.Sprintf(dnsTemplate, fqdn, ttl, "...")

	authZone, err := FindZoneByFqdn(fqdn, RecursiveNameservers)
	if err != nil {
		return err
	}

	log.Infof("acme: You can now remove this TXT record from your %s zone:", authZone)
	log.Infof("acme: %s", dnsRecord)
	return nil
}
