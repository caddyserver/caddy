package api

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/acme/api/internal/nonces"
	"github.com/xenolf/lego/acme/api/internal/secure"
	"github.com/xenolf/lego/acme/api/internal/sender"
	"github.com/xenolf/lego/log"
)

// Core ACME/LE core API.
type Core struct {
	doer         *sender.Doer
	nonceManager *nonces.Manager
	jws          *secure.JWS
	directory    acme.Directory
	HTTPClient   *http.Client

	common         service // Reuse a single struct instead of allocating one for each service on the heap.
	Accounts       *AccountService
	Authorizations *AuthorizationService
	Certificates   *CertificateService
	Challenges     *ChallengeService
	Orders         *OrderService
}

// New Creates a new Core.
func New(httpClient *http.Client, userAgent string, caDirURL, kid string, privateKey crypto.PrivateKey) (*Core, error) {
	doer := sender.NewDoer(httpClient, userAgent)

	dir, err := getDirectory(doer, caDirURL)
	if err != nil {
		return nil, err
	}

	nonceManager := nonces.NewManager(doer, dir.NewNonceURL)

	jws := secure.NewJWS(privateKey, kid, nonceManager)

	c := &Core{doer: doer, nonceManager: nonceManager, jws: jws, directory: dir, HTTPClient: httpClient}

	c.common.core = c
	c.Accounts = (*AccountService)(&c.common)
	c.Authorizations = (*AuthorizationService)(&c.common)
	c.Certificates = (*CertificateService)(&c.common)
	c.Challenges = (*ChallengeService)(&c.common)
	c.Orders = (*OrderService)(&c.common)

	return c, nil
}

// post performs an HTTP POST request and parses the response body as JSON,
// into the provided respBody object.
func (a *Core) post(uri string, reqBody, response interface{}) (*http.Response, error) {
	content, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.New("failed to marshal message")
	}

	return a.retrievablePost(uri, content, response, 0)
}

// postAsGet performs an HTTP POST ("POST-as-GET") request.
// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-6.3
func (a *Core) postAsGet(uri string, response interface{}) (*http.Response, error) {
	return a.retrievablePost(uri, []byte{}, response, 0)
}

func (a *Core) retrievablePost(uri string, content []byte, response interface{}, retry int) (*http.Response, error) {
	resp, err := a.signedPost(uri, content, response)
	if err != nil {
		// during tests, 5 retries allow to support ~50% of bad nonce.
		if retry >= 5 {
			log.Infof("too many retry on a nonce error, retry count: %d", retry)
			return resp, err
		}
		switch err.(type) {
		// Retry once if the nonce was invalidated
		case *acme.NonceError:
			log.Infof("nonce error retry: %s", err)
			resp, err = a.retrievablePost(uri, content, response, retry+1)
			if err != nil {
				return resp, err
			}
		default:
			return resp, err
		}
	}

	return resp, nil
}

func (a *Core) signedPost(uri string, content []byte, response interface{}) (*http.Response, error) {
	signedContent, err := a.jws.SignContent(uri, content)
	if err != nil {
		return nil, fmt.Errorf("failed to post JWS message -> failed to sign content -> %v", err)
	}

	signedBody := bytes.NewBuffer([]byte(signedContent.FullSerialize()))

	resp, err := a.doer.Post(uri, signedBody, "application/jose+json", response)

	// nonceErr is ignored to keep the root error.
	nonce, nonceErr := nonces.GetFromResponse(resp)
	if nonceErr == nil {
		a.nonceManager.Push(nonce)
	}

	return resp, err
}

func (a *Core) signEABContent(newAccountURL, kid string, hmac []byte) ([]byte, error) {
	eabJWS, err := a.jws.SignEABContent(newAccountURL, kid, hmac)
	if err != nil {
		return nil, err
	}

	return []byte(eabJWS.FullSerialize()), nil
}

// GetKeyAuthorization Gets the key authorization
func (a *Core) GetKeyAuthorization(token string) (string, error) {
	return a.jws.GetKeyAuthorization(token)
}

func (a *Core) GetDirectory() acme.Directory {
	return a.directory
}

func getDirectory(do *sender.Doer, caDirURL string) (acme.Directory, error) {
	var dir acme.Directory
	if _, err := do.Get(caDirURL, &dir); err != nil {
		return dir, fmt.Errorf("get directory at '%s': %v", caDirURL, err)
	}

	if dir.NewAccountURL == "" {
		return dir, errors.New("directory missing new registration URL")
	}
	if dir.NewOrderURL == "" {
		return dir, errors.New("directory missing new order URL")
	}

	return dir, nil
}
