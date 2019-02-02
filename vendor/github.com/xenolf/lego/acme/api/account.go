package api

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/xenolf/lego/acme"
)

type AccountService service

// New Creates a new account.
func (a *AccountService) New(req acme.Account) (acme.ExtendedAccount, error) {
	var account acme.Account
	resp, err := a.core.post(a.core.GetDirectory().NewAccountURL, req, &account)
	location := getLocation(resp)

	if len(location) > 0 {
		a.core.jws.SetKid(location)
	}

	if err != nil {
		return acme.ExtendedAccount{Location: location}, err
	}

	return acme.ExtendedAccount{Account: account, Location: location}, nil
}

// NewEAB Creates a new account with an External Account Binding.
func (a *AccountService) NewEAB(accMsg acme.Account, kid string, hmacEncoded string) (acme.ExtendedAccount, error) {
	hmac, err := base64.RawURLEncoding.DecodeString(hmacEncoded)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: could not decode hmac key: %v", err)
	}

	eabJWS, err := a.core.signEABContent(a.core.GetDirectory().NewAccountURL, kid, hmac)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: error signing eab content: %v", err)
	}
	accMsg.ExternalAccountBinding = eabJWS

	return a.New(accMsg)
}

// Get Retrieves an account.
func (a *AccountService) Get(accountURL string) (acme.Account, error) {
	if len(accountURL) == 0 {
		return acme.Account{}, errors.New("account[get]: empty URL")
	}

	var account acme.Account
	_, err := a.core.post(accountURL, acme.Account{}, &account)
	if err != nil {
		return acme.Account{}, err
	}
	return account, nil
}

// Deactivate Deactivates an account.
func (a *AccountService) Deactivate(accountURL string) error {
	if len(accountURL) == 0 {
		return errors.New("account[deactivate]: empty URL")
	}

	req := acme.Account{Status: acme.StatusDeactivated}
	_, err := a.core.post(accountURL, req, nil)
	return err
}
