package config

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/caddy/app"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

const rsaKeySize = 2048

// initiateLetsEncrypt sets up TLS ... <TODO>
func initiateLetsEncrypt(configs []server.Config) error {
	// fill map of email address to server configs that use that email address for TLS.
	// this will help us reduce roundtrips when getting the certs.
	initMap := make(map[string][]*server.Config)
	for i := 0; i < len(configs); i++ {
		if configs[i].TLS.Certificate == "" && configs[i].TLS.Key == "" && configs[i].Port != "http" { // TODO: && !cfg.Host.IsLoopback()
			leEmail := getEmail(configs[i])
			if leEmail == "" {
				return errors.New("cannot serve HTTPS without email address OR certificate and key")
			}
			initMap[leEmail] = append(initMap[leEmail], &configs[i])
		}
	}

	for leEmail, serverConfigs := range initMap {
		leUser, err := getLetsEncryptUser(leEmail)
		if err != nil {
			return err
		}

		client := acme.NewClient("http://192.168.99.100:4000", &leUser, rsaKeySize, "5001")

		if leUser.Registration == nil {
			reg, err := client.Register()
			if err != nil {
				return errors.New("registration error: " + err.Error())
			}
			leUser.Registration = reg

			// TODO: we can just do the agreement once, when registering, right?
			err = client.AgreeToTos()
			if err != nil {
				saveLetsEncryptUser(leUser) // TODO: Might as well try, right? Error check?
				return errors.New("error agreeing to terms: " + err.Error())
			}

			err = saveLetsEncryptUser(leUser)
			if err != nil {
				return errors.New("could not save user: " + err.Error())
			}
		}

		// collect all the hostnames
		var hosts []string
		for _, cfg := range serverConfigs {
			hosts = append(hosts, cfg.Host)
		}

		// showtime: let's get free, trusted SSL certificates! yee-haw!
		certificates, err := client.ObtainCertificates(hosts)
		if err != nil {
			return errors.New("error obtaining certs: " + err.Error())
		}

		// ... that's it. pain gone. save the certs, keys, and update server configs.
		for _, cert := range certificates {
			certFolder := filepath.Join(app.DataFolder(), "letsencrypt", "sites", cert.Domain)
			os.MkdirAll(certFolder, 0700)
			// Save cert
			err = saveCertificate(cert.Certificate, filepath.Join(certFolder, cert.Domain+".crt"))
			//err = ioutil.WriteFile(filepath.Join(certFolder, cert.Domain+".crt"), cert.Certificate, 0600)
			if err != nil {
				return err
			}

			// Save private key
			//savePrivateKey(cert.PrivateKey, filepath.Join(certFolder, cert.Domain+".key"))
			err = ioutil.WriteFile(filepath.Join(certFolder, cert.Domain+".key"), cert.PrivateKey, 0600)
			if err != nil {
				return err
			}

			// Save cert metadata
			jsonBytes, err := json.MarshalIndent(&CertificateMeta{URL: cert.CertURL, Domain: cert.Domain}, "", "\t")
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(filepath.Join(certFolder, cert.Domain+".json"), jsonBytes, 0600)
			if err != nil {
				return err
			}
		}

		// it all comes down to this: filling in the file path of a valid certificate automatically
		for _, cfg := range serverConfigs {
			cfg.TLS.Certificate = filepath.Join(app.DataFolder(), "letsencrypt", "sites", cfg.Host, cfg.Host+".crt")
			cfg.TLS.Key = filepath.Join(app.DataFolder(), "letsencrypt", "sites", cfg.Host, cfg.Host+".key")
		}
	}

	return nil
}

func getEmail(cfg server.Config) string {
	leEmail := cfg.TLS.LetsEncryptEmail
	if leEmail == "" {
		leEmail = LetsEncryptEmail
	}
	if leEmail == "" {
		// TODO: get most recent email from ~/.caddy/users file
	}
	if leEmail == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Email address: ")
		var err error
		leEmail, err = reader.ReadString('\n')
		if err != nil {
			return ""
		}
		LetsEncryptEmail = leEmail
	}
	return strings.TrimSpace(leEmail)
}

func saveLetsEncryptUser(user LetsEncryptUser) error {
	// make user account folder
	userFolder := filepath.Join(app.DataFolder(), "letsencrypt", "users", user.Email)
	err := os.MkdirAll(userFolder, 0700)
	if err != nil {
		return err
	}

	// save private key file
	user.KeyFile = filepath.Join(userFolder, emailUsername(user.Email)+".key")
	err = savePrivateKey(user.key, user.KeyFile)
	if err != nil {
		return err
	}

	// save registration file
	jsonBytes, err := json.MarshalIndent(&user, "", "\t")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(userFolder, "registration.json"), jsonBytes, 0600)
}

func getLetsEncryptUser(email string) (LetsEncryptUser, error) {
	var user LetsEncryptUser

	userFolder := filepath.Join(app.DataFolder(), "letsencrypt", "users", email)
	regFile, err := os.Open(filepath.Join(userFolder, "registration.json"))
	if err != nil {
		if os.IsNotExist(err) {
			// create a new user
			return newLetsEncryptUser(email)
		}
		return user, err
	}

	err = json.NewDecoder(regFile).Decode(&user)
	if err != nil {
		return user, err
	}

	user.key, err = loadPrivateKey(user.KeyFile)
	if err != nil {
		return user, err
	}

	return user, nil
}

func newLetsEncryptUser(email string) (LetsEncryptUser, error) {
	user := LetsEncryptUser{Email: email}
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return user, errors.New("error generating private key: " + err.Error())
	}
	user.key = privateKey
	return user, nil
}

func emailUsername(email string) string {
	at := strings.Index(email, "@")
	if at == -1 {
		return email
	}
	return email[:at]
}

type LetsEncryptUser struct {
	Email        string
	Registration *acme.RegistrationResource
	KeyFile      string
	key          *rsa.PrivateKey
}

func (u LetsEncryptUser) GetEmail() string {
	return u.Email
}
func (u LetsEncryptUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u LetsEncryptUser) GetPrivateKey() *rsa.PrivateKey {
	return u.key
}

// savePrivateKey saves an RSA private key to file.
//
// Borrowed from Sebastian Erhart
// https://github.com/xenolf/lego/blob/34910bd541315993224af1f04f9b2877513e5477/crypto.go
func savePrivateKey(key *rsa.PrivateKey, file string) error {
	pemKey := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	keyOut, err := os.Create(file)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pemKey)
	keyOut.Close()
	return nil
}

// TODO: Check file permission
func saveCertificate(certBytes []byte, file string) error {
	pemCert := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certOut, err := os.Create(file)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pemCert)
	certOut.Close()
	return nil
}

// loadPrivateKey loads an RSA private key from filename.
//
// Borrowed from Sebastian Erhart
// https://github.com/xenolf/lego/blob/34910bd541315993224af1f04f9b2877513e5477/crypto.go
func loadPrivateKey(file string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
}

type CertificateMeta struct {
	Domain, URL string
}
