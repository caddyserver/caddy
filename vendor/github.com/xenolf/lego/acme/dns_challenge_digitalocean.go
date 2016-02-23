package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// DNSProviderDigitalOcean is an implementation of the DNSProvider interface
// that uses DigitalOcean's REST API to manage TXT records for a domain.
type DNSProviderDigitalOcean struct {
	apiAuthToken string
	recordIDs    map[string]int
	recordIDsMu  sync.Mutex
}

// NewDNSProviderDigitalOcean returns a new DNSProviderDigitalOcean instance.
// apiAuthToken is the personal access token created in the DigitalOcean account
// control panel, and it will be sent in bearer authorization headers.
func NewDNSProviderDigitalOcean(apiAuthToken string) (*DNSProviderDigitalOcean, error) {
	return &DNSProviderDigitalOcean{
		apiAuthToken: apiAuthToken,
		recordIDs:    make(map[string]int),
	}, nil
}

// Present creates a TXT record using the specified parameters
func (d *DNSProviderDigitalOcean) Present(domain, token, keyAuth string) error {
	// txtRecordRequest represents the request body to DO's API to make a TXT record
	type txtRecordRequest struct {
		RecordType string `json:"type"`
		Name       string `json:"name"`
		Data       string `json:"data"`
	}

	// txtRecordResponse represents a response from DO's API after making a TXT record
	type txtRecordResponse struct {
		DomainRecord struct {
			ID   int    `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
			Data string `json:"data"`
		} `json:"domain_record"`
	}

	fqdn, value, _ := DNS01Record(domain, keyAuth)

	reqURL := fmt.Sprintf("%s/v2/domains/%s/records", digitalOceanBaseURL, domain)
	reqData := txtRecordRequest{RecordType: "TXT", Name: fqdn, Data: value}
	body, err := json.Marshal(reqData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", d.apiAuthToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errInfo digitalOceanAPIError
		json.NewDecoder(resp.Body).Decode(&errInfo)
		return fmt.Errorf("HTTP %d: %s: %s", resp.StatusCode, errInfo.ID, errInfo.Message)
	}

	// Everything looks good; but we'll need the ID later to delete the record
	var respData txtRecordResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return err
	}
	d.recordIDsMu.Lock()
	d.recordIDs[fqdn] = respData.DomainRecord.ID
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProviderDigitalOcean) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := DNS01Record(domain, keyAuth)

	// get the record's unique ID from when we created it
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[fqdn]
	d.recordIDsMu.Unlock()
	if !ok {
		return fmt.Errorf("unknown record ID for '%s'", fqdn)
	}

	reqURL := fmt.Sprintf("%s/v2/domains/%s/records/%d", digitalOceanBaseURL, domain, recordID)
	req, err := http.NewRequest("DELETE", reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", d.apiAuthToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errInfo digitalOceanAPIError
		json.NewDecoder(resp.Body).Decode(&errInfo)
		return fmt.Errorf("HTTP %d: %s: %s", resp.StatusCode, errInfo.ID, errInfo.Message)
	}

	// Delete record ID from map
	d.recordIDsMu.Lock()
	delete(d.recordIDs, fqdn)
	d.recordIDsMu.Unlock()

	return nil
}

type digitalOceanAPIError struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

var digitalOceanBaseURL = "https://api.digitalocean.com"
