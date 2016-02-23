package dnsimple

import (
	"fmt"
	"time"
)

// ContactsService handles communication with the contact related
// methods of the DNSimple API.
//
// DNSimple API docs: http://developer.dnsimple.com/contacts/
type ContactsService struct {
	client *Client
}

type Contact struct {
	Id           int        `json:"id,omitempty"`
	Label        string     `json:"label,omitempty"`
	FirstName    string     `json:"first_name,omitempty"`
	LastName     string     `json:"last_name,omitempty"`
	JobTitle     string     `json:"job_title,omitempty"`
	Organization string     `json:"organization_name,omitempty"`
	Email        string     `json:"email_address,omitempty"`
	Phone        string     `json:"phone,omitempty"`
	Fax          string     `json:"fax,omitempty"`
	Address1     string     `json:"address1,omitempty"`
	Address2     string     `json:"address2,omitempty"`
	City         string     `json:"city,omitempty"`
	Zip          string     `json:"postal_code,omitempty"`
	Country      string     `json:"country,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

type contactWrapper struct {
	Contact Contact `json:"contact"`
}

// contactPath generates the resource path for given contact.
func contactPath(contact interface{}) string {
	if contact != nil {
		return fmt.Sprintf("contacts/%d", contact)
	}
	return "contacts"
}

// List the contacts.
//
// DNSimple API docs: http://developer.dnsimple.com/contacts/#list
func (s *ContactsService) List() ([]Contact, *Response, error) {
	path := contactPath(nil)
	wrappedContacts := []contactWrapper{}

	res, err := s.client.get(path, &wrappedContacts)
	if err != nil {
		return []Contact{}, res, err
	}

	contacts := []Contact{}
	for _, contact := range wrappedContacts {
		contacts = append(contacts, contact.Contact)
	}

	return contacts, res, nil
}

// Create a new contact.
//
// DNSimple API docs: http://developer.dnsimple.com/contacts/#create
func (s *ContactsService) Create(contactAttributes Contact) (Contact, *Response, error) {
	path := contactPath(nil)
	wrappedContact := contactWrapper{Contact: contactAttributes}
	returnedContact := contactWrapper{}

	res, err := s.client.post(path, wrappedContact, &returnedContact)
	if err != nil {
		return Contact{}, res, err
	}

	return returnedContact.Contact, res, nil
}

// Get fetches a contact.
//
// DNSimple API docs: http://developer.dnsimple.com/contacts/#get
func (s *ContactsService) Get(contactID int) (Contact, *Response, error) {
	path := contactPath(contactID)
	wrappedContact := contactWrapper{}

	res, err := s.client.get(path, &wrappedContact)
	if err != nil {
		return Contact{}, res, err
	}

	return wrappedContact.Contact, res, nil
}

// Update a contact.
//
// DNSimple API docs: http://developer.dnsimple.com/contacts/#update
func (s *ContactsService) Update(contactID int, contactAttributes Contact) (Contact, *Response, error) {
	path := contactPath(contactID)
	wrappedContact := contactWrapper{Contact: contactAttributes}
	returnedContact := contactWrapper{}

	res, err := s.client.put(path, wrappedContact, &returnedContact)
	if err != nil {
		return Contact{}, res, err
	}

	return returnedContact.Contact, res, nil
}

// Delete a contact.
//
// DNSimple API docs: http://developer.dnsimple.com/contacts/#delete
func (s *ContactsService) Delete(contactID int) (*Response, error) {
	path := contactPath(contactID)

	return s.client.delete(path, nil)
}
