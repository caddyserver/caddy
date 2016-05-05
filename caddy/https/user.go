package https

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// User represents a Let's Encrypt user account.
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

// GetEmail gets u's email.
func (u User) GetEmail() string {
	return u.Email
}

// GetRegistration gets u's registration resource.
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

// GetPrivateKey gets u's private key.
func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// getUser loads the user with the given email from disk.
// If the user does not exist, it will create a new one,
// but it does NOT save new users to the disk or register
// them via ACME. It does NOT prompt the user.
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
	user.key, err = loadPrivateKey(storage.UserKeyFile(email))
	if err != nil {
		return user, err
	}

	return user, nil
}

// saveUser persists a user's key and account registration
// to the file system. It does NOT register the user via ACME
// or prompt the user.
func saveUser(user User) error {
	// make user account folder
	err := os.MkdirAll(storage.User(user.Email), 0700)
	if err != nil {
		return err
	}

	// save private key file
	err = savePrivateKey(user.key, storage.UserKeyFile(user.Email))
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
// with a new private key. This function does NOT save the
// user to disk or register it via ACME. If you want to use
// a user account that might already exist, call getUser
// instead. It does NOT prompt the user.
func newUser(email string) (User, error) {
	user := User{Email: email}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return user, errors.New("error generating private key: " + err.Error())
	}
	user.key = privateKey
	return user, nil
}

// getEmail does everything it can to obtain an email
// address from the user to use for TLS for cfg. If it
// cannot get an email address, it returns empty string.
// (It will warn the user of the consequences of an
// empty email.) This function MAY prompt the user for
// input. If userPresent is false, the operator will
// NOT be prompted and an empty email may be returned.
func getEmail(cfg server.Config, userPresent bool) string {
	// First try the tls directive from the Caddyfile
	leEmail := cfg.TLS.LetsEncryptEmail
	if leEmail == "" {
		// Then try memory (command line flag or typed by user previously)
		leEmail = DefaultEmail
	}
	if leEmail == "" {
		// Then try to get most recent user email ~/.caddy/users file
		userDirs, err := ioutil.ReadDir(storage.Users())
		if err == nil {
			var mostRecent os.FileInfo
			for _, dir := range userDirs {
				if !dir.IsDir() {
					continue
				}
				if mostRecent == nil || dir.ModTime().After(mostRecent.ModTime()) {
					leEmail = dir.Name()
					DefaultEmail = leEmail // save for next time
				}
			}
		}
	}
	if leEmail == "" && userPresent {
		// Alas, we must bother the user and ask for an email address;
		// if they proceed they also agree to the SA.
		reader := bufio.NewReader(stdin)
		fmt.Println("\nYour sites will be served over HTTPS automatically using Let's Encrypt.")
		fmt.Println("By continuing, you agree to the Let's Encrypt Subscriber Agreement at:")
		fmt.Println("  " + saURL) // TODO: Show current SA link
		fmt.Println("Please enter your email address so you can recover your account if needed.")
		fmt.Println("You can leave it blank, but you'll lose the ability to recover your account.")
		fmt.Print("Email address: ")
		var err error
		leEmail, err = reader.ReadString('\n')
		if err != nil {
			return ""
		}
		leEmail = strings.TrimSpace(leEmail)
		DefaultEmail = leEmail
		Agreed = true
	}
	return leEmail
}

// promptUserAgreement prompts the user to agree to the agreement
// at agreementURL via stdin. If the agreement has changed, then pass
// true as the second argument. If this is the user's first time
// agreeing, pass false. It returns whether the user agreed or not.
func promptUserAgreement(agreementURL string, changed bool) bool {
	if changed {
		fmt.Printf("The Let's Encrypt Subscriber Agreement has changed:\n  %s\n", agreementURL)
		fmt.Print("Do you agree to the new terms? (y/n): ")
	} else {
		fmt.Printf("To continue, you must agree to the Let's Encrypt Subscriber Agreement:\n  %s\n", agreementURL)
		fmt.Print("Do you agree to the terms? (y/n): ")
	}

	reader := bufio.NewReader(stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes"
}

// stdin is used to read the user's input if prompted;
// this is changed by tests during tests.
var stdin = io.ReadWriter(os.Stdin)

// The name of the folder for accounts where the email
// address was not provided; default 'username' if you will.
const emptyEmail = "default"

// TODO: Use latest
const saURL = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
