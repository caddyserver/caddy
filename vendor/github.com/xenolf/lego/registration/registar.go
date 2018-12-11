package registration

import (
	"errors"
	"net/http"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/acme/api"
	"github.com/xenolf/lego/log"
)

// Resource represents all important information about a registration
// of which the client needs to keep track itself.
// Deprecated: will be remove in the future (acme.ExtendedAccount).
type Resource struct {
	Body acme.Account `json:"body,omitempty"`
	URI  string       `json:"uri,omitempty"`
}

type RegisterOptions struct {
	TermsOfServiceAgreed bool
}

type RegisterEABOptions struct {
	TermsOfServiceAgreed bool
	Kid                  string
	HmacEncoded          string
}

type Registrar struct {
	core *api.Core
	user User
}

func NewRegistrar(core *api.Core, user User) *Registrar {
	return &Registrar{
		core: core,
		user: user,
	}
}

// Register the current account to the ACME server.
func (r *Registrar) Register(options RegisterOptions) (*Resource, error) {
	if r == nil || r.user == nil {
		return nil, errors.New("acme: cannot register a nil client or user")
	}

	accMsg := acme.Account{
		TermsOfServiceAgreed: options.TermsOfServiceAgreed,
		Contact:              []string{},
	}

	if r.user.GetEmail() != "" {
		log.Infof("acme: Registering account for %s", r.user.GetEmail())
		accMsg.Contact = []string{"mailto:" + r.user.GetEmail()}
	}

	account, err := r.core.Accounts.New(accMsg)
	if err != nil {
		// FIXME seems impossible
		errorDetails, ok := err.(acme.ProblemDetails)
		if !ok || errorDetails.HTTPStatus != http.StatusConflict {
			return nil, err
		}
	}

	return &Resource{URI: account.Location, Body: account.Account}, nil
}

// RegisterWithExternalAccountBinding Register the current account to the ACME server.
func (r *Registrar) RegisterWithExternalAccountBinding(options RegisterEABOptions) (*Resource, error) {
	accMsg := acme.Account{
		TermsOfServiceAgreed: options.TermsOfServiceAgreed,
		Contact:              []string{},
	}

	if r.user.GetEmail() != "" {
		log.Infof("acme: Registering account for %s", r.user.GetEmail())
		accMsg.Contact = []string{"mailto:" + r.user.GetEmail()}
	}

	account, err := r.core.Accounts.NewEAB(accMsg, options.Kid, options.HmacEncoded)
	if err != nil {
		errorDetails, ok := err.(acme.ProblemDetails)
		// FIXME seems impossible
		if !ok || errorDetails.HTTPStatus != http.StatusConflict {
			return nil, err
		}
	}

	return &Resource{URI: account.Location, Body: account.Account}, nil
}

// QueryRegistration runs a POST request on the client's registration and returns the result.
//
// This is similar to the Register function,
// but acting on an existing registration link and resource.
func (r *Registrar) QueryRegistration() (*Resource, error) {
	if r == nil || r.user == nil {
		return nil, errors.New("acme: cannot query the registration of a nil client or user")
	}

	// Log the URL here instead of the email as the email may not be set
	log.Infof("acme: Querying account for %s", r.user.GetRegistration().URI)

	account, err := r.core.Accounts.Get(r.user.GetRegistration().URI)
	if err != nil {
		return nil, err
	}

	return &Resource{
		Body: account,
		// Location: header is not returned so this needs to be populated off of existing URI
		URI: r.user.GetRegistration().URI,
	}, nil
}

// DeleteRegistration deletes the client's user registration from the ACME server.
func (r *Registrar) DeleteRegistration() error {
	if r == nil || r.user == nil {
		return errors.New("acme: cannot unregister a nil client or user")
	}

	log.Infof("acme: Deleting account for %s", r.user.GetEmail())

	return r.core.Accounts.Deactivate(r.user.GetRegistration().URI)
}

// ResolveAccountByKey will attempt to look up an account using the given account key
// and return its registration resource.
func (r *Registrar) ResolveAccountByKey() (*Resource, error) {
	log.Infof("acme: Trying to resolve account by key")

	accMsg := acme.Account{OnlyReturnExisting: true}
	accountTransit, err := r.core.Accounts.New(accMsg)
	if err != nil {
		return nil, err
	}

	account, err := r.core.Accounts.Get(accountTransit.Location)
	if err != nil {
		return nil, err
	}

	return &Resource{URI: accountTransit.Location, Body: account}, nil
}
