package api

import (
	"errors"

	"github.com/xenolf/lego/acme"
)

type AuthorizationService service

// Get Gets an authorization.
func (c *AuthorizationService) Get(authzURL string) (acme.Authorization, error) {
	if len(authzURL) == 0 {
		return acme.Authorization{}, errors.New("authorization[get]: empty URL")
	}

	var authz acme.Authorization
	_, err := c.core.postAsGet(authzURL, &authz)
	if err != nil {
		return acme.Authorization{}, err
	}
	return authz, nil
}

// Deactivate Deactivates an authorization.
func (c *AuthorizationService) Deactivate(authzURL string) error {
	if len(authzURL) == 0 {
		return errors.New("authorization[deactivate]: empty URL")
	}

	var disabledAuth acme.Authorization
	_, err := c.core.post(authzURL, acme.Authorization{Status: acme.StatusDeactivated}, &disabledAuth)
	return err
}
