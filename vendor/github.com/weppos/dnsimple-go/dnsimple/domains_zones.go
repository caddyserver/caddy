package dnsimple

import (
	"fmt"
)

type zoneResponse struct {
	Zone string `json:"zone,omitempty"`
}

// GetZone downloads the Bind-like zone file.
//
// DNSimple API docs: http://developer.dnsimple.com/domains/zones/#get
func (s *DomainsService) GetZone(domain interface{}) (string, *Response, error) {
	path := fmt.Sprintf("%s/zone", domainPath(domain))
	zoneResponse := zoneResponse{}

	res, err := s.client.get(path, &zoneResponse)
	if err != nil {
		return "", res, err
	}

	return zoneResponse.Zone, res, nil
}
