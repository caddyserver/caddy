package caddytls

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/telemetry"
)

func init() {
	caddy.RegisterEventHook("ctmonitor", startMonitoring)
	initializeCTMonitor()
}

const (
	certSpotterAPIBase string = "https://api.certspotter.com/v1/issuances"
	defaultWaitTime    string = "3600"
)

var (
	ctmonitor_config string = filepath.Join(caddy.AssetsPath(), "ct_config")
	ctmonitor        CTMonitor
)

// CTConfig is the configuration for the CT monitor.
type CTConfig struct {
	IncludeSubdomains bool `json:"inlcude_subdomains"`
	IncludeWildcards  bool `json:"include_wildcards"`
	LastID            int  `json:"last_id"`
}

// CertSpotterResponse is the json response formatting that is used in the program.
type CertSpotterResponse struct {
	ID           string   `json:"id"`
	TBSSHA256    string   `json:"tbs_sha256"`
	DNSNames     []string `json:"dns_names"`
	PubKeySha256 string   `json:"pubkey_sha256"`
	Issuer       struct {
		Name         string `json:"name"`
		PubKeySha256 string `json:"pubkey_sha256"`
	} `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Cert      struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		SHA256 string `json:"sha256"`
		Data   string `json:"data"`
	} `json:"cert"`
}

// QueryConfig is the configuration information for querying.
type QueryConfig struct {
	CTConfig
	Query string
	Index int
}

// CTMonitor holds a lot of the data that is used throughout the plugin.
type CTMonitor struct {
	// caddyCerts consists of the certs that caddy serves. Key = bytes of each cert, cast to a string
	// caddyCertsSANs are the Subject Alternate Names that Caddy is hosting.
	// used for individual queries, is an element in caddyCertsSANS
	caddyCerts     map[string]struct{}
	caddyCertsSANs []string
	domainName     string

	// issuance stored in the map entry in case the keys don't match.
	// CertSpotterResponses, used in comparisons against the caddyCerts. map of bytes to issuance.
	issuance       CertSpotterResponse
	retrievedCerts map[string]CertSpotterResponse

	// configuration struct for the CTMonitor
	config QueryConfig

	// used for terminating the routine when the shutdown event is called.
	done chan struct{}

	// retryAfter will contain the string arg from the response, used for next iteration.
	// timeToWait is the numerical value of retryAfter.
	retryAfter string
	timeToWait int

	// these variables are used while processing a CertSpotter response.
	// biggestID is the most recent certID returned from CertSpotter.
	// issuanceID is compared with biggestID to determine the most recent cert to store.
	// lastIssuance tells it when to compare the biggestID with the issuanceID.
	biggestID    int
	issuanceID   int
	lastIssuance bool
}

// BuildMapEntry adds only certificates to the map of retrievedCerts, and it gets the issuanceID and compares it to the biggestID we have seen so far.
func buildMapEntry() error {
	bytes, err := base64.StdEncoding.DecodeString(ctmonitor.issuance.Cert.Data)
	if err != nil {
		return fmt.Errorf("Decoding failed: %v", err)
	}
	aKey := string(bytes)
	if _, ok := ctmonitor.retrievedCerts[aKey]; ok {
		return nil
	}
	if ctmonitor.issuance.Cert.Type == "precert" {
		return nil
	}

	ctmonitor.retrievedCerts[aKey] = ctmonitor.issuance
	if ctmonitor.lastIssuance {
		ctmonitor.issuanceID, err = strconv.Atoi(ctmonitor.issuance.ID)
		if err != nil {
			return fmt.Errorf("failed to convert issuance.ID to an int: %v", err)
		}
		if ctmonitor.issuanceID > ctmonitor.biggestID {
			ctmonitor.biggestID = ctmonitor.issuanceID
		}
	}
	return nil
}

// compareCerts compares the certificates that caddy is serving against the certificates
// that certSpotter has found, if there are any that don't match the caddy certificates,
// they are reported to the user.
func compareCerts() int {
	foundCerts := 0 // Used for testing purposes only.
	for key := range ctmonitor.retrievedCerts {
		if _, ok := ctmonitor.caddyCerts[key]; !ok {
			issuance := ctmonitor.retrievedCerts[key]
			foundCerts++
			log.Printf("[WARNING] Certificate found that caddy is not monitoring, issued by: %v\n", issuance)
			go telemetry.Append("ct_unrecognized_issuances", issuance)
		}
	}
	return foundCerts
}

// getCaddyCerts retrieves the certificates that caddy monitors and returns them
// as a map with the key being the bytes of the certificate cast to a string.
func getCaddyCerts() {
	var (
		caddyCerts = make(map[string]struct{}) // caddyCerts consists of the certificates that Caddy is serving.
		caddyDNS   = make([]string, 0)         // caddyDNS consists of the Subject Alternate Names that Caddy is hosting.
	)
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}
		certCache.RLock()
		for _, certificate := range certCache.cache {
			caddyDNS = append(caddyDNS, certificate.Names...)
			certBytes := string(certificate.Certificate.Certificate[0])
			if _, ok := caddyCerts[certBytes]; !ok {
				caddyCerts[certBytes] = struct{}{}
			}
		}
		certCache.RUnlock()
	}
	ctmonitor.caddyCerts = caddyCerts
	ctmonitor.caddyCertsSANs = caddyDNS
}

func getCertSpotterCerts() (numOfIssuanceObjects int, err error) {
	// issuanceObjects consists of the issuanceObjects returned from CertSpotter.
	var (
		issuanceObjects []CertSpotterResponse
		certQuery       string
	)

	certQuery = prepareRequestURL()
	response, err := http.Get(certQuery)
	if err != nil {
		log.Printf("[ERROR] CT monitor: %v (url=%s)", err, certQuery)
		numOfIssuanceObjects = 0
		ctmonitor.retryAfter = response.Header.Get("Retry-After")
		if ctmonitor.retryAfter == "" {
			ctmonitor.retryAfter = defaultWaitTime
		}
		return numOfIssuanceObjects, fmt.Errorf("https get request failed: %v", err)
	}
	defer response.Body.Close()

	err = json.NewDecoder(response.Body).Decode(&issuanceObjects)
	if err != nil {
		numOfIssuanceObjects = 0
		ctmonitor.retryAfter = response.Header.Get("Retry-After")
		if ctmonitor.retryAfter == "" {
			ctmonitor.retryAfter = defaultWaitTime
		}
		return numOfIssuanceObjects, fmt.Errorf("decoding json stream: %v", err)
	}

	numOfIssuanceObjects = len(issuanceObjects)
	if numOfIssuanceObjects > 0 {
		ctmonitor.lastIssuance = false
		for i, issuance := range issuanceObjects {
			ctmonitor.issuance = issuance
			if i == numOfIssuanceObjects-1 {
				ctmonitor.lastIssuance = true
			}
			err := buildMapEntry()
			if err != nil {
				return numOfIssuanceObjects, fmt.Errorf("buildMapEntry failed: %v", err)
			}
		}
	} else {
		ctmonitor.retryAfter = response.Header.Get("Retry-After")
	}
	return
}

func getLatestIndex() error {
	var holder CTConfig
	configBytes, err := ioutil.ReadFile(ctmonitor_config)
	if os.IsNotExist(err) {
		ctmonitor.config.CTConfig.LastID = 0
		return fmt.Errorf("could not load last index file: %v", err)
	}
	if err != nil {
		ctmonitor.config.CTConfig.LastID = 0
		return err
	}
	if err := json.Unmarshal(configBytes, &holder); err != nil {
		ctmonitor.config.CTConfig.LastID = 0
		return fmt.Errorf("error reading configuration file: %v", err)
	}
	ctmonitor.config.CTConfig.LastID = holder.LastID
	return nil
}

func initializeCTMonitor() {
	// check if the datastructures are nil, if so, call make on them.
	if ctmonitor.caddyCerts == nil {
		ctmonitor.caddyCerts = make(map[string]struct{})
	}
	if ctmonitor.caddyCertsSANs == nil {
		ctmonitor.caddyCertsSANs = make([]string, 0)
	}
	if ctmonitor.retrievedCerts == nil {
		ctmonitor.retrievedCerts = make(map[string]CertSpotterResponse)
	}
}

func loadConfig() error {
	configJSON, err := os.Open(ctmonitor_config)
	if os.IsNotExist(err) {
		ctmonitor.config.CTConfig.IncludeSubdomains = false
		ctmonitor.config.CTConfig.IncludeWildcards = false
		ctmonitor.config.CTConfig.LastID = 0
		err := putLatestIndex() // create the file if it didn't exist with default values.
		if err != nil {
			return fmt.Errorf("Creating ct_config failed: %v", err)
		}
		return nil
	}
	defer configJSON.Close()
	err = json.NewDecoder(configJSON).Decode(&ctmonitor.config) // make sure that this is the right part to pass in. (was originally just config.
	if err != nil {
		ctmonitor.config.CTConfig.IncludeSubdomains = false
		ctmonitor.config.CTConfig.IncludeWildcards = false
		ctmonitor.config.CTConfig.LastID = 0
		log.Printf("[ERROR] Decoding CT monitor configuration failed: %v", err)
	}
	return nil
}

// lookUpNames queries the certSpotter service for each SAN that Caddy is hosting
// It then adds them to a set and returns a map of each certificate  mapped to a string
// that contains identifying information for the cert.
func lookUpNames() error {
	// retrievedCerts is the bytes of a certificate mapped to the
	// ID, issuer name, and before/after values.
	// retrievedCerts := make(map[string]CertSpotterResponse)

	// biggestID is the most recent certificate id returned from CertSpotter.
	// timeToWait is the amount of time you need to wait before querying again.
	// initialIndex saves the starting point for domainName queries.
	var initialIndex int

	// retryAfter is the timeToWait value from the response headers.

	var err error

	initialIndex = ctmonitor.config.CTConfig.LastID

	// If the caddyCertsSANs is empty, it shouldn't run this at all.
	for _, domainName := range ctmonitor.caddyCertsSANs {
		ctmonitor.domainName = domainName
		ctmonitor.config.CTConfig.LastID = initialIndex // resets the index for the next query so that no certs are skipped.
		err = queryDomainName()
		if err != nil {
			return fmt.Errorf("queryDomainName encountered error: %v", err)
		}
	}
	err = putLatestIndex()
	if err != nil {
		return fmt.Errorf("[ERROR] writing latest ID failed, err: %v", err)
	}
	ctmonitor.timeToWait, err = strconv.Atoi(ctmonitor.retryAfter)
	if err != nil {
		log.Printf("[ERROR] Bad Retry-After value from CT server: %v", err)
		ctmonitor.timeToWait, _ = strconv.Atoi(defaultWaitTime)
	}
	// returning retrievedCerts because it is created here and timeToWait
	// so that ctmonitor waits enough time before trying again.
	return err
}

// monitorCerts continuously monitors the certificates that Caddy serves,
// it queries again after the specified time.
func monitorCerts() {
	ctmonitor.timeToWait = 0
	err := loadConfig()

	if err != nil {
		log.Printf("[ERROR] loading config: %v", err)
		return
	}
	for {
		select {
		case <-ctmonitor.done:
			return // if shutdown signal received from Caddy, stop the thread.
		case <-time.After(time.Duration(ctmonitor.timeToWait)):
			getCaddyCerts()
			if len(ctmonitor.caddyCertsSANs) == 0 {
				log.Println("[INFO] Caddy is not serving any certificates; CT monitor disabled.")
			}
			err := getLatestIndex()
			if err != nil {
				log.Printf("[ERROR] Getting starting index: %v", err)
				break
			}
			ctmonitor.config.Query = certSpotterAPIBase
			err = lookUpNames()
			// compareCerts runs even if there was an error.  If the error occurred after
			// retrieving all of the certs, we can still compare them before quitting.
			compareCerts()
			if err != nil {
				log.Printf("[ERROR] lookUpNames encountered an error %v, terminating ctmonitor.", err)
				break
			}
		}
	}
}

func prepareRequestURL() (query string) {
	v := url.Values{}
	v.Set("domain", ctmonitor.domainName)
	if ctmonitor.config.CTConfig.IncludeWildcards {
		v.Set("match_wildcards", "true")
	}
	if ctmonitor.config.CTConfig.IncludeSubdomains {
		v.Set("include_subdomains", "true")
	}
	v.Set("after", strconv.Itoa(ctmonitor.config.CTConfig.LastID))
	v.Add("expand", "dns_names")
	v.Add("expand", "issuer")
	v.Add("expand", "cert")
	encodedValue := v.Encode()
	query = ctmonitor.config.Query + "?" + encodedValue
	return query
}

func putLatestIndex() error {
	file, err := os.Create(ctmonitor_config)
	fmt.Println(ctmonitor_config)
	if err != nil {
		return fmt.Errorf("Opening %s file for writing: %v", ctmonitor_config, err)
	}
	defer file.Close()
	err = json.NewEncoder(file).Encode(ctmonitor.config.CTConfig)
	if err != nil {
		return fmt.Errorf("writing CT monitor config: %v", err)
	}
	return nil
}

func queryDomainName() error {
	// numOfIssuanceObjects is used for paging the responses
	var numOfIssuanceObjects int
	var err error
	for ok := true; ok; ok = numOfIssuanceObjects > 0 {
		numOfIssuanceObjects, err = getCertSpotterCerts()
		if err != nil {
			return fmt.Errorf("error getting certs from certSpotter: %v", err)
		}
	}
	return nil
}

func startMonitoring(eventType caddy.EventName, eventInfo interface{}) error {
	if eventType == caddy.StartupEvent { // caddy.InstanceStartUpEvent
		go monitorCerts()

	} else if eventType == caddy.ShutdownEvent {
		ctmonitor.done <- struct{}{}
	}
	return nil
}

func String() string {
	return fmt.Sprintf("ID: %v IssuerName: %s Not valid before: %s Not valid after: %s", ctmonitor.issuance.Cert.ID, ctmonitor.issuance.Issuer.Name, ctmonitor.issuance.NotBefore, ctmonitor.issuance.NotAfter)
}
