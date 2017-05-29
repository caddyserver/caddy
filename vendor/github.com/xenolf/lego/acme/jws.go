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

	"gopkg.in/square/go-jose.v1"
)

type jws struct {
	directoryURL string
	privKey      crypto.PrivateKey
	nonces       nonceManager
}

func keyAsJWK(key interface{}) *jose.JsonWebKey {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return &jose.JsonWebKey{Key: k, Algorithm: "EC"}
	case *rsa.PublicKey:
		return &jose.JsonWebKey{Key: k, Algorithm: "RSA"}

	default:
		return nil
	}
}

// Posts a JWS signed message to the specified URL.
// It does NOT close the response body, so the caller must
// do that if no error was returned.
func (j *jws) post(url string, content []byte) (*http.Response, error) {
	signedContent, err := j.signContent(content)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign content -> %s", err.Error())
	}

	resp, err := httpPost(url, "application/jose+json", bytes.NewBuffer([]byte(signedContent.FullSerialize())))
	if err != nil {
		return nil, fmt.Errorf("Failed to HTTP POST to %s -> %s", url, err.Error())
	}

	nonce, nonceErr := getNonceFromResponse(resp)
	if nonceErr == nil {
		j.nonces.Push(nonce)
	}

	return resp, nil
}

func (j *jws) signContent(content []byte) (*jose.JsonWebSignature, error) {

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

	signer, err := jose.NewSigner(alg, j.privKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create jose signer -> %s", err.Error())
	}
	signer.SetNonceSource(j)

	signed, err := signer.Sign(content)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign content -> %s", err.Error())
	}
	return signed, nil
}

func (j *jws) Nonce() (string, error) {
	if nonce, ok := j.nonces.Pop(); ok {
		return nonce, nil
	}

	return getNonce(j.directoryURL)
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
		return "", fmt.Errorf("Failed to get nonce from HTTP HEAD -> %s", err.Error())
	}

	return getNonceFromResponse(resp)
}

func getNonceFromResponse(resp *http.Response) (string, error) {
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("Server did not respond with a proper nonce header.")
	}

	return nonce, nil
}
