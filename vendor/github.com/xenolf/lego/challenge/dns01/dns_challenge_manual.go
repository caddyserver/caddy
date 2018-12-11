package dns01

import (
	"bufio"
	"fmt"
	"os"
)

const (
	dnsTemplate = `%s %d IN TXT "%s"`
)

// DNSProviderManual is an implementation of the ChallengeProvider interface
type DNSProviderManual struct{}

// NewDNSProviderManual returns a DNSProviderManual instance.
func NewDNSProviderManual() (*DNSProviderManual, error) {
	return &DNSProviderManual{}, nil
}

// Present prints instructions for manually creating the TXT record
func (*DNSProviderManual) Present(domain, token, keyAuth string) error {
	fqdn, value := GetRecord(domain, keyAuth)

	authZone, err := FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	fmt.Printf("lego: Please create the following TXT record in your %s zone:\n", authZone)
	fmt.Printf(dnsTemplate+"\n", fqdn, DefaultTTL, value)
	fmt.Printf("lego: Press 'Enter' when you are done\n")

	_, err = bufio.NewReader(os.Stdin).ReadBytes('\n')

	return err
}

// CleanUp prints instructions for manually removing the TXT record
func (*DNSProviderManual) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := GetRecord(domain, keyAuth)

	authZone, err := FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	fmt.Printf("lego: You can now remove this TXT record from your %s zone:\n", authZone)
	fmt.Printf(dnsTemplate+"\n", fqdn, DefaultTTL, "...")

	return nil
}
