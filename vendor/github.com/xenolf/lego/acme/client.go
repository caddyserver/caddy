// Package acme implements the ACME protocol for Let's Encrypt and other conforming providers.
package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Logger is an optional custom logger.
	Logger *log.Logger
)

const (
	// maxBodySize is the maximum size of body that we will read.
	maxBodySize = 1024 * 1024

	// overallRequestLimit is the overall number of request per second limited on the
	// “new-reg”, “new-authz” and “new-cert” endpoints. From the documentation the
	// limitation is 20 requests per second, but using 20 as value doesn't work but 18 do
	overallRequestLimit = 18
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
	GetPrivateKey() crypto.PrivateKey
}

// Interface for all challenge solvers to implement.
type solver interface {
	Solve(challenge challenge, domain string) error
}

type validateFunc func(j *jws, domain, uri string, chlng challenge) error

// Client is the user-friendy way to ACME
type Client struct {
	directory directory
	user      User
	jws       *jws
	keyType   KeyType
	solvers   map[Challenge]solver
}

// NewClient creates a new ACME client on behalf of the user. The client will depend on
// the ACME directory located at caDirURL for the rest of its actions.  A private
// key of type keyType (see KeyType contants) will be generated when requesting a new
// certificate if one isn't provided.
func NewClient(caDirURL string, user User, keyType KeyType) (*Client, error) {
	privKey := user.GetPrivateKey()
	if privKey == nil {
		return nil, errors.New("private key was nil")
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

	return &Client{directory: dir, user: user, jws: jws, keyType: keyType, solvers: solvers}, nil
}

// SetChallengeProvider specifies a custom provider p that can solve the given challenge type.
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
//
// NOTE: This REPLACES any custom HTTP provider previously set by calling
// c.SetChallengeProvider with the default HTTP challenge provider.
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
//
// NOTE: This REPLACES any custom TLS-SNI provider previously set by calling
// c.SetChallengeProvider with the default TLS-SNI challenge provider.
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
	var regURI string
	hdr, err := postJSON(c.jws, c.directory.NewRegURL, regMsg, &serverReg)
	if err != nil {
		remoteErr, ok := err.(RemoteError)
		if ok && remoteErr.StatusCode == 409 {
			regURI = hdr.Get("Location")
			regMsg = registrationMessage{
				Resource: "reg",
			}
			if hdr, err = postJSON(c.jws, regURI, regMsg, &serverReg); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	reg := &RegistrationResource{Body: serverReg}

	links := parseLinks(hdr["Link"])

	if regURI == "" {
		regURI = hdr.Get("Location")
	}
	reg.URI = regURI
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

// DeleteRegistration deletes the client's user registration from the ACME
// server.
func (c *Client) DeleteRegistration() error {
	if c == nil || c.user == nil {
		return errors.New("acme: cannot unregister a nil client or user")
	}
	logf("[INFO] acme: Deleting account for %s", c.user.GetEmail())

	regMsg := registrationMessage{
		Resource: "reg",
		Delete:   true,
	}

	_, err := postJSON(c.jws, c.user.GetRegistration().URI, regMsg, nil)
	if err != nil {
		return err
	}

	return nil
}

// QueryRegistration runs a POST request on the client's registration and
// returns the result.
//
// This is similar to the Register function, but acting on an existing
// registration link and resource.
func (c *Client) QueryRegistration() (*RegistrationResource, error) {
	if c == nil || c.user == nil {
		return nil, errors.New("acme: cannot query the registration of a nil client or user")
	}
	// Log the URL here instead of the email as the email may not be set
	logf("[INFO] acme: Querying account for %s", c.user.GetRegistration().URI)

	regMsg := registrationMessage{
		Resource: "reg",
	}

	var serverReg Registration
	hdr, err := postJSON(c.jws, c.user.GetRegistration().URI, regMsg, &serverReg)
	if err != nil {
		return nil, err
	}

	reg := &RegistrationResource{Body: serverReg}

	links := parseLinks(hdr["Link"])
	// Location: header is not returned so this needs to be populated off of
	// existing URI
	reg.URI = c.user.GetRegistration().URI
	if links["terms-of-service"] != "" {
		reg.TosURL = links["terms-of-service"]
	}

	if links["next"] != "" {
		reg.NewAuthzURL = links["next"]
	} else {
		return nil, errors.New("acme: No new-authz link in response to registration query")
	}

	return reg, nil
}

// AgreeToTOS updates the Client registration and sends the agreement to
// the server.
func (c *Client) AgreeToTOS() error {
	reg := c.user.GetRegistration()

	reg.Body.Agreement = c.user.GetRegistration().TosURL
	reg.Body.Resource = "reg"
	_, err := postJSON(c.jws, c.user.GetRegistration().URI, c.user.GetRegistration().Body, nil)
	return err
}

// ObtainCertificateForCSR tries to obtain a certificate matching the CSR passed into it.
// The domains are inferred from the CommonName and SubjectAltNames, if any. The private key
// for this CSR is not required.
// If bundle is true, the []byte contains both the issuer certificate and
// your issued certificate as a bundle.
// This function will never return a partial certificate. If one domain in the list fails,
// the whole certificate will fail.
func (c *Client) ObtainCertificateForCSR(csr x509.CertificateRequest, bundle bool) (CertificateResource, map[string]error) {
	// figure out what domains it concerns
	// start with the common name
	domains := []string{csr.Subject.CommonName}

	// loop over the SubjectAltName DNS names
DNSNames:
	for _, sanName := range csr.DNSNames {
		for _, existingName := range domains {
			if existingName == sanName {
				// duplicate; skip this name
				continue DNSNames
			}
		}

		// name is unique
		domains = append(domains, sanName)
	}

	if bundle {
		logf("[INFO][%s] acme: Obtaining bundled SAN certificate given a CSR", strings.Join(domains, ", "))
	} else {
		logf("[INFO][%s] acme: Obtaining SAN certificate given a CSR", strings.Join(domains, ", "))
	}

	challenges, failures := c.getChallenges(domains)
	// If any challenge fails - return. Do not generate partial SAN certificates.
	if len(failures) > 0 {
		for _, auth := range challenges {
			c.disableAuthz(auth)
		}

		return CertificateResource{}, failures
	}

	errs := c.solveChallenges(challenges)
	// If any challenge fails - return. Do not generate partial SAN certificates.
	if len(errs) > 0 {
		return CertificateResource{}, errs
	}

	logf("[INFO][%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	cert, err := c.requestCertificateForCsr(challenges, bundle, csr.Raw, nil)
	if err != nil {
		for _, chln := range challenges {
			failures[chln.Domain] = err
		}
	}

	// Add the CSR to the certificate so that it can be used for renewals.
	cert.CSR = pemEncode(&csr)

	return cert, failures
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
func (c *Client) ObtainCertificate(domains []string, bundle bool, privKey crypto.PrivateKey, mustStaple bool) (CertificateResource, map[string]error) {
	if bundle {
		logf("[INFO][%s] acme: Obtaining bundled SAN certificate", strings.Join(domains, ", "))
	} else {
		logf("[INFO][%s] acme: Obtaining SAN certificate", strings.Join(domains, ", "))
	}

	challenges, failures := c.getChallenges(domains)
	// If any challenge fails - return. Do not generate partial SAN certificates.
	if len(failures) > 0 {
		for _, auth := range challenges {
			c.disableAuthz(auth)
		}

		return CertificateResource{}, failures
	}

	errs := c.solveChallenges(challenges)
	// If any challenge fails - return. Do not generate partial SAN certificates.
	if len(errs) > 0 {
		return CertificateResource{}, errs
	}

	logf("[INFO][%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	cert, err := c.requestCertificate(challenges, bundle, privKey, mustStaple)
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
func (c *Client) RenewCertificate(cert CertificateResource, bundle, mustStaple bool) (CertificateResource, error) {
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

	// We always need to request a new certificate to renew.
	// Start by checking to see if the certificate was based off a CSR, and
	// use that if it's defined.
	if len(cert.CSR) > 0 {
		csr, err := pemDecodeTox509CSR(cert.CSR)
		if err != nil {
			return CertificateResource{}, err
		}
		newCert, failures := c.ObtainCertificateForCSR(*csr, bundle)
		return newCert, failures[cert.Domain]
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

	newCert, failures := c.ObtainCertificate(domains, bundle, privKey, mustStaple)
	return newCert, failures[cert.Domain]
}

// Looks through the challenge combinations to find a solvable match.
// Then solves the challenges in series and returns.
func (c *Client) solveChallenges(challenges []authorizationResource) map[string]error {
	// loop through the resources, basically through the domains.
	failures := make(map[string]error)
	for _, authz := range challenges {
		if authz.Body.Status == "valid" {
			// Boulder might recycle recent validated authz (see issue #267)
			logf("[INFO][%s] acme: Authorization already valid; skipping challenge", authz.Domain)
			continue
		}
		// no solvers - no solving
		if solvers := c.chooseSolvers(authz.Body, authz.Domain); solvers != nil {
			for i, solver := range solvers {
				// TODO: do not immediately fail if one domain fails to validate.
				err := solver.Solve(authz.Body.Challenges[i], authz.Domain)
				if err != nil {
					c.disableAuthz(authz)
					failures[authz.Domain] = err
				}
			}
		} else {
			c.disableAuthz(authz)
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

	delay := time.Second / overallRequestLimit

	for _, domain := range domains {
		time.Sleep(delay)

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
				errc <- domainError{Domain: domain, Error: errors.New("Server did not provide next link to proceed")}
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

	logAuthz(challenges)

	close(resc)
	close(errc)

	return challenges, failures
}

func logAuthz(authz []authorizationResource) {
	for _, auth := range authz {
		logf("[INFO][%s] AuthURL: %s", auth.Domain, auth.AuthURL)
	}
}

// cleanAuthz loops through the passed in slice and disables any auths which are not "valid"
func (c *Client) disableAuthz(auth authorizationResource) error {
	var disabledAuth authorization
	_, err := postJSON(c.jws, auth.AuthURL, deactivateAuthMessage{Resource: "authz", Status: "deactivated"}, &disabledAuth)
	return err
}

func (c *Client) requestCertificate(authz []authorizationResource, bundle bool, privKey crypto.PrivateKey, mustStaple bool) (CertificateResource, error) {
	if len(authz) == 0 {
		return CertificateResource{}, errors.New("Passed no authorizations to requestCertificate!")
	}

	var err error
	if privKey == nil {
		privKey, err = generatePrivateKey(c.keyType)
		if err != nil {
			return CertificateResource{}, err
		}
	}

	// determine certificate name(s) based on the authorization resources
	commonName := authz[0]
	var san []string
	for _, auth := range authz[1:] {
		san = append(san, auth.Domain)
	}

	// TODO: should the CSR be customizable?
	csr, err := generateCsr(privKey, commonName.Domain, san, mustStaple)
	if err != nil {
		return CertificateResource{}, err
	}

	return c.requestCertificateForCsr(authz, bundle, csr, pemEncode(privKey))
}

func (c *Client) requestCertificateForCsr(authz []authorizationResource, bundle bool, csr []byte, privateKeyPem []byte) (CertificateResource, error) {
	commonName := authz[0]

	var authURLs []string
	for _, auth := range authz[1:] {
		authURLs = append(authURLs, auth.AuthURL)
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

	certRes := CertificateResource{
		Domain:     commonName.Domain,
		CertURL:    resp.Header.Get("Location"),
		PrivateKey: privateKeyPem,
	}

	maxChecks := 1000
	for i := 0; i < maxChecks; i++ {
		done, err := c.checkCertResponse(resp, &certRes, bundle)
		resp.Body.Close()
		if err != nil {
			return CertificateResource{}, err
		}
		if done {
			break
		}
		if i == maxChecks-1 {
			return CertificateResource{}, fmt.Errorf("polled for certificate %d times; giving up", i)
		}
		resp, err = httpGet(certRes.CertURL)
		if err != nil {
			return CertificateResource{}, err
		}
	}

	return certRes, nil
}

// checkCertResponse checks resp to see if a certificate is contained in the
// response, and if so, loads it into certRes and returns true. If the cert
// is not yet ready, it returns false. This function honors the waiting period
// required by the Retry-After header of the response, if specified. This
// function may read from resp.Body but does NOT close it. The certRes input
// should already have the Domain (common name) field populated. If bundle is
// true, the certificate will be bundled with the issuer's cert.
func (c *Client) checkCertResponse(resp *http.Response, certRes *CertificateResource, bundle bool) (bool, error) {
	switch resp.StatusCode {
	case 201, 202:
		cert, err := ioutil.ReadAll(limitReader(resp.Body, maxBodySize))
		if err != nil {
			return false, err
		}

		// The server returns a body with a length of zero if the
		// certificate was not ready at the time this request completed.
		// Otherwise the body is the certificate.
		if len(cert) > 0 {
			certRes.CertStableURL = resp.Header.Get("Content-Location")
			certRes.AccountRef = c.user.GetRegistration().URI

			issuedCert := pemEncode(derCertificateBytes(cert))

			// The issuer certificate link is always supplied via an "up" link
			// in the response headers of a new certificate.
			links := parseLinks(resp.Header["Link"])
			issuerCert, err := c.getIssuerCertificate(links["up"])
			if err != nil {
				// If we fail to acquire the issuer cert, return the issued certificate - do not fail.
				logf("[WARNING][%s] acme: Could not bundle issuer certificate: %v", certRes.Domain, err)
			} else {
				issuerCert = pemEncode(derCertificateBytes(issuerCert))

				// If bundle is true, we want to return a certificate bundle.
				// To do this, we append the issuer cert to the issued cert.
				if bundle {
					issuedCert = append(issuedCert, issuerCert...)
				}
			}

			certRes.Certificate = issuedCert
			certRes.IssuerCertificate = issuerCert
			logf("[INFO][%s] Server responded with a certificate.", certRes.Domain)
			return true, nil
		}

		// The certificate was granted but is not yet issued.
		// Check retry-after and loop.
		ra := resp.Header.Get("Retry-After")
		retryAfter, err := strconv.Atoi(ra)
		if err != nil {
			return false, err
		}

		logf("[INFO][%s] acme: Server responded with status 202; retrying after %ds", certRes.Domain, retryAfter)
		time.Sleep(time.Duration(retryAfter) * time.Second)

		return false, nil
	default:
		return false, handleHTTPError(resp)
	}
}

// getIssuerCertificate requests the issuer certificate
func (c *Client) getIssuerCertificate(url string) ([]byte, error) {
	logf("[INFO] acme: Requesting issuer cert from %s", url)
	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	issuerBytes, err := ioutil.ReadAll(limitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}

	_, err = x509.ParseCertificate(issuerBytes)
	if err != nil {
		return nil, err
	}

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
