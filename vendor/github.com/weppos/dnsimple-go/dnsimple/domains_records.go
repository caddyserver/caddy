package dnsimple

import (
	"fmt"
	"net/url"
	"time"
)

type Record struct {
	Id        int        `json:"id,omitempty"`
	DomainId  int        `json:"domain_id,omitempty"`
	Name      string     `json:"name,omitempty"`
	Content   string     `json:"content,omitempty"`
	TTL       int        `json:"ttl,omitempty"`
	Priority  int        `json:"prio,omitempty"`
	Type      string     `json:"record_type,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type recordWrapper struct {
	Record Record `json:"record"`
}

// recordPath generates the resource path for given record that belongs to a domain.
func recordPath(domain interface{}, record interface{}) string {
	path := fmt.Sprintf("domains/%s/records", domainIdentifier(domain))

	if record != nil {
		path += fmt.Sprintf("/%d", record)
	}

	return path
}

// List the domain records.
//
// DNSimple API docs: http://developer.dnsimple.com/domains/records/#list
func (s *DomainsService) ListRecords(domain interface{}, recordName, recordType string) ([]Record, *Response, error) {
	reqStr := recordPath(domain, nil)
	v := url.Values{}

	if recordName != "" {
		v.Add("name", recordName)
	}
	if recordType != "" {
		v.Add("type", recordType)
	}
	reqStr += "?" + v.Encode()

	wrappedRecords := []recordWrapper{}

	res, err := s.client.get(reqStr, &wrappedRecords)
	if err != nil {
		return []Record{}, res, err
	}

	records := []Record{}
	for _, record := range wrappedRecords {
		records = append(records, record.Record)
	}

	return records, res, nil
}

// CreateRecord creates a domain record.
//
// DNSimple API docs: http://developer.dnsimple.com/domains/records/#create
func (s *DomainsService) CreateRecord(domain interface{}, recordAttributes Record) (Record, *Response, error) {
	path := recordPath(domain, nil)
	wrappedRecord := recordWrapper{Record: recordAttributes}
	returnedRecord := recordWrapper{}

	res, err := s.client.post(path, wrappedRecord, &returnedRecord)
	if err != nil {
		return Record{}, res, err
	}

	return returnedRecord.Record, res, nil
}

// GetRecord fetches the domain record.
//
// DNSimple API docs: http://developer.dnsimple.com/domains/records/#get
func (s *DomainsService) GetRecord(domain interface{}, recordID int) (Record, *Response, error) {
	path := recordPath(domain, recordID)
	wrappedRecord := recordWrapper{}

	res, err := s.client.get(path, &wrappedRecord)
	if err != nil {
		return Record{}, res, err
	}

	return wrappedRecord.Record, res, nil
}

// UpdateRecord updates a domain record.
//
// DNSimple API docs: http://developer.dnsimple.com/domains/records/#update
func (s *DomainsService) UpdateRecord(domain interface{}, recordID int, recordAttributes Record) (Record, *Response, error) {
	path := recordPath(domain, recordID)
	// name, content, ttl, priority
	wrappedRecord := recordWrapper{
		Record: Record{
			Name:     recordAttributes.Name,
			Content:  recordAttributes.Content,
			TTL:      recordAttributes.TTL,
			Priority: recordAttributes.Priority}}
	returnedRecord := recordWrapper{}

	res, err := s.client.put(path, wrappedRecord, &returnedRecord)
	if err != nil {
		return Record{}, res, err
	}

	return returnedRecord.Record, res, nil
}

// DeleteRecord deletes a domain record.
//
// DNSimple API docs: http://developer.dnsimple.com/domains/records/#delete
func (s *DomainsService) DeleteRecord(domain interface{}, recordID int) (*Response, error) {
	path := recordPath(domain, recordID)

	return s.client.delete(path, nil)
}

// UpdateIP updates the IP of specific A record.
//
// This is not part of the standard API. However,
// this is useful for Dynamic DNS (DDNS or DynDNS).
func (record *Record) UpdateIP(client *Client, IP string) error {
	newRecord := Record{Content: IP, Name: record.Name}
	_, _, err := client.Domains.UpdateRecord(record.DomainId, record.Id, newRecord)
	return err
}
