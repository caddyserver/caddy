// Package acme implements the ACME protocol for Let's Encrypt and other conforming providers.
package acme

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Logger is an optional custom logger.
	Logger *log.Logger
)

// logf writes a log entry. It uses Logger if not
// nil, otherwise it uses the default log.Logger.
func logf(format string, args ...interface{}) {
	if Logger != nil {
		Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// User interface is to be implemented by users of this library.
// It is used by the client type to get user specific information.
type User interface {
	GetEmail() string
	GetRegistration() *RegistrationResource
	GetPrivateKey() *rsa.PrivateKey
}

// Interface for all challenge solvers to implement.
type solver interface {
	Solve(challenge challenge, domain string) error
}

type validateFunc func(j *jws, domain, uri string, chlng challenge) error

// Client is the user-friendy way to ACME
type Client struct {
	directory  directory
	user       User
	jws        *jws
	keyBits    int
	issuerCert []byte
	solvers    map[Challenge]solver
}

// NewClient creates a new ACME client on behalf of the user. The client will depend on
// the ACME directory located at caDirURL for the rest of its actions. It will
// generate private keys for certificates of size keyBits.
func NewClient(caDirURL string, user User, keyBits int) (*Client, error) {
	privKey := user.GetPrivateKey()
	if privKey == nil {
		return nil, errors.New("private key was nil")
	}

	if err := privKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	var dir directory
	if _, err := getJSON(caDirURL, &dir); err != nil {
		return nil, fmt.Errorf("get directory at '%s': %v", caDirURL, err)
	}

	if dir.NewRegURL == "" {
		return nil, errors.New("directory missing new registration URL")
	}
	if dir.NewAuthzURL == "" {
		return nil, errors.New("directory missing new authz URL")
	}
	if dir.NewCertURL == "" {
		return nil, errors.New("directory missing new certificate URL")
	}
	if dir.RevokeCertURL == "" {
		return nil, errors.New("directory missing revoke certificate URL")
	}

	jws := &jws{privKey: privKey, directoryURL: caDirURL}

	// REVIEW: best possibility?
	// Add all available solvers with the right index as per ACME
	// spec to this map. Otherwise they won`t be found.
	solvers := make(map[Challenge]solver)
	solvers[HTTP01] = &httpChallenge{jws: jws, validate: validate, provider: &HTTPProviderServer{}}
	solvers[TLSSNI01] = &tlsSNIChallenge{jws: jws, validate: validate, provider: &TLSProviderServer{}}

	return &Client{directory: dir, user: user, jws: jws, keyBits: keyBits, solvers: solvers}, nil
}

// SetChallengeProvider specifies a custom provider that will make the solution available
func (c *Client) SetChallengeProvider(challenge Challenge, p ChallengeProvider) error {
	switch challenge {
	case HTTP01:
		c.solvers[challenge] = &httpChallenge{jws: c.jws, validate: validate, provider: p}
	case TLSSNI01:
		c.solvers[challenge] = &tlsSNIChallenge{jws: c.jws, validate: validate, provider: p}
	case DNS01:
		c.solvers[challenge] = &dnsChallenge{jws: c.jws, validate: validate, provider: p}
	default:
		return fmt.Errorf("Unknown challenge %v", challenge)
	}
	return nil
}

// SetHTTPAddress specifies a custom interface:port to be used for HTTP based challenges.
// If this option is not used, the default port 80 and all interfaces will be used.
// To only specify a port and no interface use the ":port" notation.
func (c *Client) SetHTTPAddress(iface string) error {
	host, port, err := net.SplitHostPort(iface)
	if err != nil {
		return err
	}

	if chlng, ok := c.solvers[HTTP01]; ok {
		chlng.(*httpChallenge).provider = NewHTTPProviderServer(host, port)
	}

	return nil
}

// SetTLSAddress specifies a custom interface:port to be used for TLS based challenges.
// If this option is not used, the default port 443 and all interfaces will be used.
// To only specify a port and no interface use the ":port" notation.
func (c *Client) SetTLSAddress(iface string) error {
	host, port, err := net.SplitHostPort(iface)
	if err != nil {
		return err
	}

	if chlng, ok := c.solvers[TLSSNI01]; ok {
		chlng.(*tlsSNIChallenge).provider = NewTLSProviderServer(host, port)
	}
	return nil
}

// ExcludeChallenges explicitly removes challenges from the pool for solving.
func (c *Client) ExcludeChallenges(challenges []Challenge) {
	// Loop through all challenges and delete the requested one if found.
	for _, challenge := range challenges {
		delete(c.solvers, challenge)
	}
}

// Register the current account to the ACME server.
func (c *Client) Register() (*RegistrationResource, error) {
	if c == nil || c.user == nil {
		return nil, errors.New("acme: cannot register a nil client or user")
	}
	logf("[INFO] acme: Registering account for %s", c.user.GetEmail())

	regMsg := registrationMessage{
		Resource: "new-reg",
	}
	if c.user.GetEmail() != "" {
		regMsg.Contact = []string{"mailto:" + c.user.GetEmail()}
	} else {
		regMsg.Contact = []string{}
	}

	var serverReg Registration
	hdr, err := postJSON(c.jws, c.directory.NewRegURL, regMsg, &serverReg)
	if err != nil {
		return nil, err
	}

	reg := &RegistrationResource{Body: serverReg}

	links := parseLinks(hdr["Link"])
	reg.URI = hdr.Get("Location")
	if links["terms-of-service"] != "" {
		reg.TosURL = links["terms-of-service"]
	}

	if links["next"] != "" {
		reg.NewAuthzURL = links["next"]
	} else {
		return nil, errors.New("acme: The server did not return 'next' link to proceed")
	}

	return reg, nil
}

// AgreeToTOS updates the Client registration and sends the agreement to
// the server.
func (c *Client) AgreeToTOS() error {
	c.user.GetRegistration().Body.Agreement = c.user.GetRegistration().TosURL
	c.user.GetRegistration().Body.Resource = "reg"
	_, err := postJSON(c.jws, c.user.GetRegistration().URI, c.user.GetRegistration().Body, nil)
	return err
}

// ObtainCertificate tries to obtain a single certificate using all domains passed into it.
// The first domain in domains is used for the CommonName field of the certificate, all other
// domains are added using the Subject Alternate Names extension. A new private key is generated
// for every invocation of this function. If you do not want that you can supply your own private key
// in the privKey parameter. If this parameter is non-nil it will be used instead of generating a new one.
// If bundle is true, the []byte contains both the issuer certificate and
// your issued certificate as a bundle.
// This function will never return a partial certificate. If one domain in the list fails,
// the whole certificate will fail.
func (c *Client) ObtainCertificate(domains []string, bundle bool, privKey crypto.PrivateKey) (CertificateResource, map[string]error) {
	if bundle {
		logf("[INFO][%s] acme: Obtaining bundled SAN certificate", strings.Join(domains, ", "))
	} else {
		logf("[INFO][%s] acme: Obtaining SAN certificate", strings.Join(domains, ", "))
	}

	challenges, failures := c.getChallenges(domains)
	// If any challenge fails - return. Do not generate partial SAN certificates.
	if len(failures) > 0 {
		return CertificateResource{}, failures
	}

	errs := c.solveChallenges(challenges)
	// If any challenge fails - return. Do not generate partial SAN certificates.
	if len(errs) > 0 {
		return CertificateResource{}, errs
	}

	logf("[INFO][%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	cert, err := c.requestCertificate(challenges, bundle, privKey)
	if err != nil {
		for _, chln := range challenges {
			failures[chln.Domain] = err
		}
	}

	return cert, failures
}

// RevokeCertificate takes a PEM encoded certificate or bundle and tries to revoke it at the CA.
func (c *Client) RevokeCertificate(certificate []byte) error {
	certificates, err := parsePEMBundle(certificate)
	if err != nil {
		return err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return fmt.Errorf("Certificate bundle starts with a CA certificate")
	}

	encodedCert := base64.URLEncoding.EncodeToString(x509Cert.Raw)

	_, err = postJSON(c.jws, c.directory.RevokeCertURL, revokeCertMessage{Resource: "revoke-cert", Certificate: encodedCert}, nil)
	return err
}

// RenewCertificate takes a CertificateResource and tries to renew the certificate.
// If the renewal process succeeds, the new certificate will ge returned in a new CertResource.
// Please be aware that this function will return a new certificate in ANY case that is not an error.
// If the server does not provide us with a new cert on a GET request to the CertURL
// this function will start a new-cert flow where a new certificate gets generated.
// If bundle is true, the []byte contains both the issuer certificate and
// your issued certificate as a bundle.
// For private key reuse the PrivateKey property of the passed in CertificateResource should be non-nil.
func (c *Client) RenewCertificate(cert CertificateResource, bundle bool) (CertificateResource, error) {
	// Input certificate is PEM encoded. Decode it here as we may need the decoded
	// cert later on in the renewal process. The input may be a bundle or a single certificate.
	certificates, err := parsePEMBundle(cert.Certificate)
	if err != nil {
		return CertificateResource{}, err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return CertificateResource{}, fmt.Errorf("[%s] Certificate bundle starts with a CA certificate", cert.Domain)
	}

	// This is just meant to be informal for the user.
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	logf("[INFO][%s] acme: Trying renewal with %d hours remaining", cert.Domain, int(timeLeft.Hours()))

	// The first step of renewal is to check if we get a renewed cert
	// directly from the cert URL.
	resp, err := httpGet(cert.CertURL)
	if err != nil {
		return CertificateResource{}, err
	}
	defer resp.Body.Close()
	serverCertBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return CertificateResource{}, err
	}

	serverCert, err := x509.ParseCertificate(serverCertBytes)
	if err != nil {
		return CertificateResource{}, err
	}

	// If the server responds with a different certificate we are effectively renewed.
	// TODO: Further test if we can actually use the new certificate (Our private key works)
	if !x509Cert.Equal(serverCert) {
		logf("[INFO][%s] acme: Server responded with renewed certificate", cert.Domain)
		issuedCert := pemEncode(derCertificateBytes(serverCertBytes))
		// If bundle is true, we want to return a certificate bundle.
		// To do this, we need the issuer certificate.
		if bundle {
			// The issuer certificate link is always supplied via an "up" link
			// in the response headers of a new certificate.
			links := parseLinks(resp.Header["Link"])
			issuerCert, err := c.getIssuerCertificate(links["up"])
			if err != nil {
				// If we fail to acquire the issuer cert, return the issued certificate - do not fail.
				logf("[ERROR][%s] acme: Could not bundle issuer certificate: %v", cert.Domain, err)
			} else {
				// Success - append the issuer cert to the issued cert.
				issuerCert = pemEncode(derCertificateBytes(issuerCert))
				issuedCert = append(issuedCert, issuerCert...)
				cert.Certificate = issuedCert
			}
		}

		cert.Certificate = issuedCert
		return cert, nil
	}

	var privKey crypto.PrivateKey
	if cert.PrivateKey != nil {
		privKey, err = parsePEMPrivateKey(cert.PrivateKey)
		if err != nil {
			return CertificateResource{}, err
		}
	}

	var domains []string
	var failures map[string]error
	// check for SAN certificate
	if len(x509Cert.DNSNames) > 1 {
		domains = append(domains, x509Cert.Subject.CommonName)
		for _, sanDomain := range x509Cert.DNSNames {
			if sanDomain == x509Cert.Subject.CommonName {
				continue
			}
			domains = append(domains, sanDomain)
		}
	} else {
		domains = append(domains, x509Cert.Subject.CommonName)
	}

	newCert, failures := c.ObtainCertificate(domains, bundle, privKey)
	return newCert, failures[cert.Domain]
}

// Looks through the challenge combinations to find a solvable match.
// Then solves the challenges in series and returns.
func (c *Client) solveChallenges(challenges []authorizationResource) map[string]error {
	// loop through the resources, basically through the domains.
	failures := make(map[string]error)
	for _, authz := range challenges {
		// no solvers - no solving
		if solvers := c.chooseSolvers(authz.Body, authz.Domain); solvers != nil {
			for i, solver := range solvers {
				// TODO: do not immediately fail if one domain fails to validate.
				err := solver.Solve(authz.Body.Challenges[i], authz.Domain)
				if err != nil {
					failures[authz.Domain] = err
				}
			}
		} else {
			failures[authz.Domain] = fmt.Errorf("[%s] acme: Could not determine solvers", authz.Domain)
		}
	}

	return failures
}

// Checks all combinations from the server and returns an array of
// solvers which should get executed in series.
func (c *Client) chooseSolvers(auth authorization, domain string) map[int]solver {
	for _, combination := range auth.Combinations {
		solvers := make(map[int]solver)
		for _, idx := range combination {
			if solver, ok := c.solvers[auth.Challenges[idx].Type]; ok {
				solvers[idx] = solver
			} else {
				logf("[INFO][%s] acme: Could not find solver for: %s", domain, auth.Challenges[idx].Type)
			}
		}

		// If we can solve the whole combination, return the solvers
		if len(solvers) == len(combination) {
			return solvers
		}
	}
	return nil
}

// Get the challenges needed to proof our identifier to the ACME server.
func (c *Client) getChallenges(domains []string) ([]authorizationResource, map[string]error) {
	resc, errc := make(chan authorizationResource), make(chan domainError)

	for _, domain := range domains {
		go func(domain string) {
			authMsg := authorization{Resource: "new-authz", Identifier: identifier{Type: "dns", Value: domain}}
			var authz authorization
			hdr, err := postJSON(c.jws, c.user.GetRegistration().NewAuthzURL, authMsg, &authz)
			if err != nil {
				errc <- domainError{Domain: domain, Error: err}
				return
			}

			links := parseLinks(hdr["Link"])
			if links["next"] == "" {
				logf("[ERROR][%s] acme: Server did not provide next link to proceed", domain)
				return
			}

			resc <- authorizationResource{Body: authz, NewCertURL: links["next"], AuthURL: hdr.Get("Location"), Domain: domain}
		}(domain)
	}

	responses := make(map[string]authorizationResource)
	failures := make(map[string]error)
	for i := 0; i < len(domains); i++ {
		select {
		case res := <-resc:
			responses[res.Domain] = res
		case err := <-errc:
			failures[err.Domain] = err.Error
		}
	}

	challenges := make([]authorizationResource, 0, len(responses))
	for _, domain := range domains {
		if challenge, ok := responses[domain]; ok {
			challenges = append(challenges, challenge)
		}
	}

	close(resc)
	close(errc)

	return challenges, failures
}

func (c *Client) requestCertificate(authz []authorizationResource, bundle bool, privKey crypto.PrivateKey) (CertificateResource, error) {
	if len(authz) == 0 {
		return CertificateResource{}, errors.New("Passed no authorizations to requestCertificate!")
	}

	commonName := authz[0]
	var err error
	if privKey == nil {
		privKey, err = generatePrivateKey(rsakey, c.keyBits)
		if err != nil {
			return CertificateResource{}, err
		}
	}

	var san []string
	var authURLs []string
	for _, auth := range authz[1:] {
		san = append(san, auth.Domain)
		authURLs = append(authURLs, auth.AuthURL)
	}

	// TODO: should the CSR be customizable?
	csr, err := generateCsr(privKey.(*rsa.PrivateKey), commonName.Domain, san)
	if err != nil {
		return CertificateResource{}, err
	}

	csrString := base64.URLEncoding.EncodeToString(csr)
	jsonBytes, err := json.Marshal(csrMessage{Resource: "new-cert", Csr: csrString, Authorizations: authURLs})
	if err != nil {
		return CertificateResource{}, err
	}

	resp, err := c.jws.post(commonName.NewCertURL, jsonBytes)
	if err != nil {
		return CertificateResource{}, err
	}

	privateKeyPem := pemEncode(privKey)
	cerRes := CertificateResource{
		Domain:     commonName.Domain,
		CertURL:    resp.Header.Get("Location"),
		PrivateKey: privateKeyPem}

	for {
		switch resp.StatusCode {
		case 201, 202:
			cert, err := ioutil.ReadAll(limitReader(resp.Body, 1024*1024))
			resp.Body.Close()
			if err != nil {
				return CertificateResource{}, err
			}

			// The server returns a body with a length of zero if the
			// certificate was not ready at the time this request completed.
			// Otherwise the body is the certificate.
			if len(cert) > 0 {

				cerRes.CertStableURL = resp.Header.Get("Content-Location")

				issuedCert := pemEncode(derCertificateBytes(cert))
				// If bundle is true, we want to return a certificate bundle.
				// To do this, we need the issuer certificate.
				if bundle {
					// The issuer certificate link is always supplied via an "up" link
					// in the response headers of a new certificate.
					links := parseLinks(resp.Header["Link"])
					issuerCert, err := c.getIssuerCertificate(links["up"])
					if err != nil {
						// If we fail to acquire the issuer cert, return the issued certificate - do not fail.
						logf("[WARNING][%s] acme: Could not bundle issuer certificate: %v", commonName.Domain, err)
					} else {
						// Success - append the issuer cert to the issued cert.
						issuerCert = pemEncode(derCertificateBytes(issuerCert))
						issuedCert = append(issuedCert, issuerCert...)
					}
				}

				cerRes.Certificate = issuedCert
				logf("[INFO][%s] Server responded with a certificate.", commonName.Domain)
				return cerRes, nil
			}

			// The certificate was granted but is not yet issued.
			// Check retry-after and loop.
			ra := resp.Header.Get("Retry-After")
			retryAfter, err := strconv.Atoi(ra)
			if err != nil {
				return CertificateResource{}, err
			}

			logf("[INFO][%s] acme: Server responded with status 202; retrying after %ds", commonName.Domain, retryAfter)
			time.Sleep(time.Duration(retryAfter) * time.Second)

			break
		default:
			return CertificateResource{}, handleHTTPError(resp)
		}

		resp, err = httpGet(cerRes.CertURL)
		if err != nil {
			return CertificateResource{}, err
		}
	}
}

// getIssuerCertificate requests the issuer certificate and caches it for
// subsequent requests.
func (c *Client) getIssuerCertificate(url string) ([]byte, error) {
	logf("[INFO] acme: Requesting issuer cert from %s", url)
	if c.issuerCert != nil {
		return c.issuerCert, nil
	}

	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	issuerBytes, err := ioutil.ReadAll(limitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	_, err = x509.ParseCertificate(issuerBytes)
	if err != nil {
		return nil, err
	}

	c.issuerCert = issuerBytes
	return issuerBytes, err
}

func parseLinks(links []string) map[string]string {
	aBrkt := regexp.MustCompile("[<>]")
	slver := regexp.MustCompile("(.+) *= *\"(.+)\"")
	linkMap := make(map[string]string)

	for _, link := range links {

		link = aBrkt.ReplaceAllString(link, "")
		parts := strings.Split(link, ";")

		matches := slver.FindStringSubmatch(parts[1])
		if len(matches) > 0 {
			linkMap[matches[2]] = parts[0]
		}
	}

	return linkMap
}

// validate makes the ACME server start validating a
// challenge response, only returning once it is done.
func validate(j *jws, domain, uri string, chlng challenge) error {
	var challengeResponse challenge

	hdr, err := postJSON(j, uri, chlng, &challengeResponse)
	if err != nil {
		return err
	}

	// After the path is sent, the ACME server will access our server.
	// Repeatedly check the server for an updated status on our request.
	for {
		switch challengeResponse.Status {
		case "valid":
			logf("[INFO][%s] The server validated our request", domain)
			return nil
		case "pending":
			break
		case "invalid":
			return handleChallengeError(challengeResponse)
		default:
			return errors.New("The server returned an unexpected state.")
		}

		ra, err := strconv.Atoi(hdr.Get("Retry-After"))
		if err != nil {
			// The ACME server MUST return a Retry-After.
			// If it doesn't, we'll just poll hard.
			ra = 1
		}
		time.Sleep(time.Duration(ra) * time.Second)

		hdr, err = getJSON(uri, &challengeResponse)
		if err != nil {
			return err
		}
	}
}
