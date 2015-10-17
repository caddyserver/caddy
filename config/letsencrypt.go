package config

// TODO: This code is a mess but I'm cleaning it up locally and
// refactoring a bunch. It will have tests, too. Don't worry. :)

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
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/caddy/app"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// Some essential values related to the Let's Encrypt process
const (
	// Size of RSA keys in bits
	rsaKeySize = 2048

	// The base URL to the Let's Encrypt CA
	caURL = "http://192.168.99.100:4000"

	// The port to expose to the CA server for Simple HTTP Challenge
	exposePort = "5001"
)

// initiateLetsEncrypt sets up TLS for each server config
// in configs as needed. It only skips the config if the
// cert and key are already specified or if plaintext http
// is explicitly specified as the port.
func initiateLetsEncrypt(configs []server.Config) ([]server.Config, error) {
	// populate map of email address to server configs that use that email address for TLS.
	// this will help us reduce roundtrips when getting the certs.
	initMap := make(map[string][]*server.Config)
	for i := 0; i < len(configs); i++ {
		if configs[i].TLS.Certificate == "" && configs[i].TLS.Key == "" && configs[i].Port != "http" { // TODO: && !cfg.Host.IsLoopback()
			leEmail := getEmail(configs[i])
			if leEmail == "" {
				return configs, errors.New("cannot serve HTTPS without email address OR certificate and key")
			}
			initMap[leEmail] = append(initMap[leEmail], &configs[i])
		}
	}

	// Loop through each email address and obtain certs; we can obtain more
	// than one certificate per email address, and still save them individually.
	for leEmail, serverConfigs := range initMap {
		// Look up or create the LE user account
		leUser, err := getLetsEncryptUser(leEmail)
		if err != nil {
			return configs, err
		}

		// The client facilitates our communication with the CA server.
		client := acme.NewClient(caURL, &leUser, rsaKeySize, exposePort)

		// If not registered, the user must register an account with the CA
		// and agree to terms
		if leUser.Registration == nil {
			reg, err := client.Register()
			if err != nil {
				return configs, errors.New("registration error: " + err.Error())
			}
			leUser.Registration = reg

			// TODO: we can just do the agreement once, when registering, right?
			err = client.AgreeToTos()
			if err != nil {
				saveLetsEncryptUser(leUser) // TODO: Might as well try, right? Error check?
				return configs, errors.New("error agreeing to terms: " + err.Error())
			}

			err = saveLetsEncryptUser(leUser)
			if err != nil {
				return configs, errors.New("could not save user: " + err.Error())
			}
		}

		// collect all the hostnames into one slice
		var hosts []string
		for _, cfg := range serverConfigs {
			hosts = append(hosts, cfg.Host)
		}

		// showtime: let's get free, trusted SSL certificates! yeah!
		certificates, err := client.ObtainCertificates(hosts)
		if err != nil {
			return configs, errors.New("error obtaining certs: " + err.Error())
		}

		// ... that's it. save the certs, keys, and update server configs.
		for _, cert := range certificates {
			certFolder := filepath.Join(app.DataFolder(), "letsencrypt", "sites", cert.Domain)
			os.MkdirAll(certFolder, 0700)

			// Save cert
			err = saveCertificate(cert.Certificate, filepath.Join(certFolder, cert.Domain+".crt"))
			if err != nil {
				return configs, err
			}

			// Save private key
			err = ioutil.WriteFile(filepath.Join(certFolder, cert.Domain+".key"), cert.PrivateKey, 0600)
			if err != nil {
				return configs, err
			}

			// Save cert metadata
			jsonBytes, err := json.MarshalIndent(&CertificateMeta{URL: cert.CertURL, Domain: cert.Domain}, "", "\t")
			if err != nil {
				return configs, err
			}
			err = ioutil.WriteFile(filepath.Join(certFolder, cert.Domain+".json"), jsonBytes, 0600)
			if err != nil {
				return configs, err
			}
		}

		// it all comes down to this: filling in the file path of a valid certificate automatically
		for _, cfg := range serverConfigs {
			cfg.TLS.Certificate = filepath.Join(app.DataFolder(), "letsencrypt", "sites", cfg.Host, cfg.Host+".crt")
			cfg.TLS.Key = filepath.Join(app.DataFolder(), "letsencrypt", "sites", cfg.Host, cfg.Host+".key")
			cfg.TLS.Enabled = true
			cfg.Port = "https"

			// Is there a plaintext HTTP config for the same host? If not, make
			// one and have it redirect all requests to this HTTPS host.
			var plaintextHostFound bool
			for _, otherCfg := range configs {
				if cfg.Host == otherCfg.Host && otherCfg.Port == "http" {
					plaintextHostFound = true
					break
				}
			}

			if !plaintextHostFound {
				// Make one that redirects to HTTPS for all requests
				configs = append(configs, redirPlaintextHost(*cfg))
			}
		}
	}

	return configs, nil
}

// redirPlaintextHost returns a new virtualhost configuration for a server
// that redirects the plaintext HTTP host of cfg to cfg, which is assumed
// to be the secure (HTTPS) host.
func redirPlaintextHost(cfg server.Config) server.Config {
	redirMidware := func(next middleware.Handler) middleware.Handler {
		return redirect.Redirect{Next: next, Rules: []redirect.Rule{
			{
				FromScheme: "http",
				FromPath:   "/",
				To:         "https://" + cfg.Host + "{uri}",
				Code:       http.StatusMovedPermanently,
			},
		}}
	}

	return server.Config{
		Host: cfg.Host,
		Port: "http",
		Middleware: map[string][]middleware.Middleware{
			"/": []middleware.Middleware{redirMidware},
		},
	}
}

// getEmail does everything it can to obtain an email
// address from the user to use for TLS for cfg. If it
// cannot get an email address, it returns empty string.
func getEmail(cfg server.Config) string {
	// First try the tls directive from the Caddyfile
	leEmail := cfg.TLS.LetsEncryptEmail
	if leEmail == "" {
		// Then try memory (command line flag or typed by user previously)
		leEmail = LetsEncryptEmail
	}
	if leEmail == "" {
		// Then try to get most recent user email ~/.caddy/users file
		// TODO: Probably better to open the user's json file and read the email out of there...
		userDirs, err := ioutil.ReadDir(filepath.Join(app.DataFolder(), "letsencrypt", "users"))
		if err == nil {
			var mostRecent os.FileInfo
			for _, dir := range userDirs {
				if !dir.IsDir() {
					continue
				}
				if mostRecent == nil || dir.ModTime().After(mostRecent.ModTime()) {
					mostRecent = dir
				}
			}
			leEmail = mostRecent.Name()
		}
	}
	if leEmail == "" {
		// Alas, we must bother the user and ask for an email address
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Email address: ") // TODO: More explanation probably, and show ToS?
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
