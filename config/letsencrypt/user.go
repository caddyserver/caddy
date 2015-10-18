package letsencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/xenolf/lego/acme"
)

type User struct {
	Email        string
	Registration *acme.RegistrationResource
	KeyFile      string
	key          *rsa.PrivateKey
}

func (u User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u User) GetPrivateKey() *rsa.PrivateKey {
	return u.key
}

// getUser loads the user with the given email from disk.
func getUser(email string) (User, error) {
	var user User

	// open user file
	regFile, err := os.Open(storage.UserRegFile(email))
	if err != nil {
		if os.IsNotExist(err) {
			// create a new user
			return newUser(email)
		}
		return user, err
	}
	defer regFile.Close()

	// load user information
	err = json.NewDecoder(regFile).Decode(&user)
	if err != nil {
		return user, err
	}

	// load their private key
	user.key, err = loadRSAPrivateKey(user.KeyFile)
	if err != nil {
		return user, err
	}

	return user, nil
}

// saveUser persists a user's key and account registration
// to the file system.
func saveUser(user User) error {
	// make user account folder
	err := os.MkdirAll(storage.User(user.Email), 0700)
	if err != nil {
		return err
	}

	// save private key file
	user.KeyFile = storage.UserKeyFile(user.Email)
	err = saveRSAPrivateKey(user.key, user.KeyFile)
	if err != nil {
		return err
	}

	// save registration file
	jsonBytes, err := json.MarshalIndent(&user, "", "\t")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(storage.UserRegFile(user.Email), jsonBytes, 0600)
}

// newUser creates a new User for the given email address
// with a new private key. This function does not register
// the user via ACME.
func newUser(email string) (User, error) {
	user := User{Email: email}
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return user, errors.New("error generating private key: " + err.Error())
	}
	user.key = privateKey
	return user, nil
}
