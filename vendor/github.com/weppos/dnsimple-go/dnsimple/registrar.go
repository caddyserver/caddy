package dnsimple

import (
	"fmt"
)

// RegistrarService handles communication with the registrar related
// methods of the DNSimple API.
//
// DNSimple API docs: http://developer.dnsimple.com/registrar/
type RegistrarService struct {
	client *Client
}

// ExtendedAttributes maps the additional attributes required by some registries.
type ExtendedAttributes map[string]string

// ExtendedAttributes represents the transfer information.
type TransferOrder struct {
	AuthCode string `json:"authinfo,omitempty"`
}

// registrationRequest represents the body of a register or transfer request.
type registrationRequest struct {
	Domain             Domain              `json:"domain"`
	ExtendedAttributes *ExtendedAttributes `json:"extended_attribute,omitempty"`
	TransferOrder      *TransferOrder      `json:"transfer_order,omitempty"`
}

// IsAvailable checks if the domain is available or registered.
//
// See: http://developer.dnsimple.com/registrar/#check
func (s *RegistrarService) IsAvailable(domain string) (bool, error) {
	path := fmt.Sprintf("%s/check", domainPath(domain))

	res, err := s.client.get(path, nil)
	if err != nil && res != nil && res.StatusCode != 404 {
		return false, err
	}

	return res.StatusCode == 404, nil
}

// Register a domain.
//
// DNSimple API docs: http://developer.dnsimple.com/registrar/#register
func (s *RegistrarService) Register(domain string, registrantID int, extendedAttributes *ExtendedAttributes) (Domain, *Response, error) {
	request := registrationRequest{
		Domain:             Domain{Name: domain, RegistrantId: registrantID},
		ExtendedAttributes: extendedAttributes,
	}
	returnedDomain := domainWrapper{}

	res, err := s.client.post("domain_registrations", request, &returnedDomain)
	if err != nil {
		return Domain{}, res, err
	}

	return returnedDomain.Domain, res, nil
}

// Transfer a domain.
//
// DNSimple API docs: http://developer.dnsimple.com/registrar/#transfer
func (s *RegistrarService) Transfer(domain string, registrantID int, authCode string, extendedAttributes *ExtendedAttributes) (Domain, *Response, error) {
	request := registrationRequest{
		Domain:             Domain{Name: domain, RegistrantId: registrantID},
		ExtendedAttributes: extendedAttributes,
		TransferOrder:      &TransferOrder{AuthCode: authCode},
	}
	returnedDomain := domainWrapper{}

	res, err := s.client.post("domain_transfers", request, &returnedDomain)
	if err != nil {
		return Domain{}, res, err
	}

	return returnedDomain.Domain, res, nil
}

// renewDomain represents the body of a Renew request.
type renewDomain struct {
	Name              string `json:"name,omitempty"`
	RenewWhoisPrivacy bool   `json:"renew_whois_privacy,omitempty"`
}

// Renew the domain, optionally renewing WHOIS privacy service.
//
// DNSimple API docs: http://developer.dnsimple.com/registrar/#renew
func (s *RegistrarService) Renew(domain string, renewWhoisPrivacy bool) (Domain, *Response, error) {
	request := domainRequest{Domain: renewDomain{
		Name:              domain,
		RenewWhoisPrivacy: renewWhoisPrivacy,
	}}
	returnedDomain := domainWrapper{}

	res, err := s.client.post("domain_renewals", request, &returnedDomain)
	if err != nil {
		return Domain{}, res, err
	}

	return returnedDomain.Domain, res, nil
}

// EnableAutoRenewal enables the auto-renewal feature for the domain.
//
// DNSimple API docs: http://developer.dnsimple.com/registrar/autorenewal/#enable
func (s *RegistrarService) EnableAutoRenewal(domain interface{}) (*Response, error) {
	path := fmt.Sprintf("%s/auto_renewal", domainPath(domain))

	res, err := s.client.post(path, nil, nil)
	if err != nil {
		return res, err
	}

	return res, nil
}

// DisableAutoRenewal disables the auto-renewal feature for the domain.
//
// DNSimple API docs: http://developer.dnsimple.com/registrar/autorenewal/#disable
func (s *RegistrarService) DisableAutoRenewal(domain interface{}) (*Response, error) {
	path := fmt.Sprintf("%s/auto_renewal", domainPath(domain))

	res, err := s.client.delete(path, nil)
	if err != nil {
		return res, err
	}

	return res, nil
}
