package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"net/http"
	"sync"

	"gopkg.in/square/go-jose.v2"
)

type jws struct {
	getNonceURL string
	privKey     crypto.PrivateKey
	kid         string
	nonces      nonceManager
}

// Posts a JWS signed message to the specified URL.
// It does NOT close the response body, so the caller must
// do that if no error was returned.
func (j *jws) post(url string, content []byte) (*http.Response, error) {
	signedContent, err := j.signContent(url, content)
	if err != nil {
		return nil, fmt.Errorf("failed to sign content -> %s", err.Error())
	}

	data := bytes.NewBuffer([]byte(signedContent.FullSerialize()))
	resp, err := httpPost(url, "application/jose+json", data)
	if err != nil {
		return nil, fmt.Errorf("failed to HTTP POST to %s -> %s", url, err.Error())
	}

	nonce, nonceErr := getNonceFromResponse(resp)
	if nonceErr == nil {
		j.nonces.Push(nonce)
	}

	return resp, nil
}

func (j *jws) signContent(url string, content []byte) (*jose.JSONWebSignature, error) {

	var alg jose.SignatureAlgorithm
	switch k := j.privKey.(type) {
	case *rsa.PrivateKey:
		alg = jose.RS256
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			alg = jose.ES256
		} else if k.Curve == elliptic.P384() {
			alg = jose.ES384
		}
	}

	jsonKey := jose.JSONWebKey{
		Key:   j.privKey,
		KeyID: j.kid,
	}

	signKey := jose.SigningKey{
		Algorithm: alg,
		Key:       jsonKey,
	}
	options := jose.SignerOptions{
		NonceSource:  j,
		ExtraHeaders: make(map[jose.HeaderKey]interface{}),
	}
	options.ExtraHeaders["url"] = url
	if j.kid == "" {
		options.EmbedJWK = true
	}

	signer, err := jose.NewSigner(signKey, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer -> %s", err.Error())
	}

	signed, err := signer.Sign(content)
	if err != nil {
		return nil, fmt.Errorf("failed to sign content -> %s", err.Error())
	}
	return signed, nil
}

func (j *jws) signEABContent(url, kid string, hmac []byte) (*jose.JSONWebSignature, error) {
	jwk := jose.JSONWebKey{Key: j.privKey}
	jwkJSON, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("acme: error encoding eab jwk key: %s", err.Error())
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmac},
		&jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": kid,
				"url": url,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create External Account Binding jose signer -> %s", err.Error())
	}

	signed, err := signer.Sign(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to External Account Binding sign content -> %s", err.Error())
	}

	return signed, nil
}

func (j *jws) Nonce() (string, error) {
	if nonce, ok := j.nonces.Pop(); ok {
		return nonce, nil
	}

	return getNonce(j.getNonceURL)
}

type nonceManager struct {
	nonces []string
	sync.Mutex
}

func (n *nonceManager) Pop() (string, bool) {
	n.Lock()
	defer n.Unlock()

	if len(n.nonces) == 0 {
		return "", false
	}

	nonce := n.nonces[len(n.nonces)-1]
	n.nonces = n.nonces[:len(n.nonces)-1]
	return nonce, true
}

func (n *nonceManager) Push(nonce string) {
	n.Lock()
	defer n.Unlock()
	n.nonces = append(n.nonces, nonce)
}

func getNonce(url string) (string, error) {
	resp, err := httpHead(url)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce from HTTP HEAD -> %s", err.Error())
	}

	return getNonceFromResponse(resp)
}

func getNonceFromResponse(resp *http.Response) (string, error) {
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("server did not respond with a proper nonce header")
	}

	return nonce, nil
}
