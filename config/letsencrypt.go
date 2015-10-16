package config

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/xenolf/lego/acme"
)

func NewLetsEncryptUser(email string) (LetsEncryptUser, error) {
	user := LetsEncryptUser{Email: email}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return user, errors.New("error generating private key: " + err.Error())
	}
	user.Key = privateKey
	return user, nil
}

type LetsEncryptUser struct {
	Email        string
	Registration *acme.RegistrationResource
	Key          *rsa.PrivateKey
}

func (u LetsEncryptUser) GetEmail() string {
	return u.Email
}
func (u LetsEncryptUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u LetsEncryptUser) GetPrivateKey() *rsa.PrivateKey {
	return u.Key
}
