package acme

import (
	"fmt"
	"os"
	"strings"

	"github.com/weppos/dnsimple-go/dnsimple"
)

// DNSProviderDNSimple is an implementation of the DNSProvider interface.
type DNSProviderDNSimple struct {
	client *dnsimple.Client
}

// NewDNSProviderDNSimple returns a DNSProviderDNSimple instance with a configured dnsimple client.
// Authentication is either done using the passed credentials or - when empty - using the environment
// variables DNSIMPLE_EMAIL and DNSIMPLE_API_KEY.
func NewDNSProviderDNSimple(dnsimpleEmail, dnsimpleAPIKey string) (*DNSProviderDNSimple, error) {
	if dnsimpleEmail == "" || dnsimpleAPIKey == "" {
		dnsimpleEmail, dnsimpleAPIKey = dnsimpleEnvAuth()
		if dnsimpleEmail == "" || dnsimpleAPIKey == "" {
			return nil, fmt.Errorf("DNSimple credentials missing")
		}
	}

	c := &DNSProviderDNSimple{
		client: dnsimple.NewClient(dnsimpleAPIKey, dnsimpleEmail),
	}

	return c, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProviderDNSimple) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := DNS01Record(domain, keyAuth)

	zoneID, zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return err
	}

	recordAttributes := c.newTxtRecord(zoneName, fqdn, value, ttl)
	_, _, err = c.client.Domains.CreateRecord(zoneID, *recordAttributes)
	if err != nil {
		return fmt.Errorf("DNSimple API call failed: %v", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProviderDNSimple) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := DNS01Record(domain, keyAuth)

	records, err := c.findTxtRecords(domain, fqdn)
	if err != nil {
		return err
	}

	for _, rec := range records {
		_, err := c.client.Domains.DeleteRecord(rec.DomainId, rec.Id)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *DNSProviderDNSimple) getHostedZone(domain string) (string, string, error) {
	domains, _, err := c.client.Domains.List()
	if err != nil {
		return "", "", fmt.Errorf("DNSimple API call failed: %v", err)
	}

	var hostedDomain dnsimple.Domain
	for _, d := range domains {
		if strings.HasSuffix(domain, d.Name) {
			if len(d.Name) > len(hostedDomain.Name) {
				hostedDomain = d
			}
		}
	}
	if hostedDomain.Id == 0 {
		return "", "", fmt.Errorf("No matching DNSimple domain found for domain %s", domain)
	}

	return fmt.Sprintf("%v", hostedDomain.Id), hostedDomain.Name, nil
}

func (c *DNSProviderDNSimple) findTxtRecords(domain, fqdn string) ([]dnsimple.Record, error) {
	zoneID, zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	var records []dnsimple.Record
	result, _, err := c.client.Domains.ListRecords(zoneID, "", "TXT")
	if err != nil {
		return records, fmt.Errorf("DNSimple API call has failed: %v", err)
	}

	recordName := c.extractRecordName(fqdn, zoneName)
	for _, record := range result {
		if record.Name == recordName {
			records = append(records, record)
		}
	}

	return records, nil
}

func (c *DNSProviderDNSimple) newTxtRecord(zone, fqdn, value string, ttl int) *dnsimple.Record {
	name := c.extractRecordName(fqdn, zone)

	return &dnsimple.Record{
		Type:    "TXT",
		Name:    name,
		Content: value,
		TTL:     ttl,
	}
}

func (c *DNSProviderDNSimple) extractRecordName(fqdn, domain string) string {
	name := unFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func dnsimpleEnvAuth() (email, apiKey string) {
	email = os.Getenv("DNSIMPLE_EMAIL")
	apiKey = os.Getenv("DNSIMPLE_API_KEY")
	if len(email) == 0 || len(apiKey) == 0 {
		return "", ""
	}
	return
}
