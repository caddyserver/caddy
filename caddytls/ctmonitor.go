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
	"strings"
	"time"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterEventHook("ctmonitor", startMonitoring)
}

const (
	certSpotterAPIBase string = "https://api.certspotter.com/v1/issuances"
)

var (
	filePath     string = filepath.Join(caddy.AssetsPath(), "ct_id")
	ctConfigFile string = filepath.Join(caddy.AssetsPath(), "ct_config")
)

// CtConfig struct will allow me to get the config data from a file
type CtConfig struct {
	IncludeSubdomains bool `json:"subdomains"`
	IncludeWildCards  bool `json:"wildCards"`
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

// QueryConfig is the configuration information for my queries.
type QueryConfig struct {
	Subdomains bool
	WildCards  bool
	Query      string
	Index      int
}

// CompareCerts compares the certificates that caddy is serving against the certificates
// that certSpotter has found, if there are any that don't match the caddy certificates,
// they are reported to the user.
func CompareCerts(caddyCerts map[string]struct{}, certSpotterCerts map[string]string) {
	for key := range certSpotterCerts {
		if _, ok := caddyCerts[key]; !ok {
			log.Printf("[WARNING] Certificate found that caddy is not monitoring, issued by: %v\n", certSpotterCerts[key])
		}
	}
}

// getCaddyCerts retrieves the certificates that caddy monitors and returns them
// as a map with the key being the bytes of the certificate cast to a string.
func getCaddyCerts() ([]string, map[string]struct{}) {
	var (
		caddyCerts = make(map[string]struct{}) //caddyCerts consists of the certificates that Caddy is serving.
		caddyDNS   = make([]string, 0, 10)     //caddyDNS consists of the Subject Alternate Names that Caddy is hosting.
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
	return caddyDNS, caddyCerts
}

func getLatestIndex(fileName string) (int, error) {
	fmt.Printf("ct_id FilePath: %v\n", fileName)
	indexBytes, err := ioutil.ReadFile(fileName)
	if os.IsNotExist(err) {
		log.Println("getLatestIndex failed, could not find the file")
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	indexStr := strings.TrimSpace(string(indexBytes))
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		log.Println("Error converting file string to int.")
		return 0, err
	}
	return index, nil
}

func loadConfig() (config CtConfig) {
	configJSON, err := os.Open(ctConfigFile)
	if err != nil {
		log.Printf("loadConfig error: %v", err)
	}
	defer configJSON.Close()
	//var config Config
	err = json.NewDecoder(configJSON).Decode(&config)
	if err != nil {
		log.Printf("[NOTICE] jsonDecode failed, error: %v\nUsing default values", err)
		config.IncludeSubdomains = false
		config.IncludeWildCards = false
	}
	return
}

// lookUpNames queries the certSpotter service for each SAN that Caddy is hosting
// It then adds them to a set and returns a map of each certificate  mapped to a string
// that contains identifying information for the cert.
func lookUpNames(caddyCertsSANs []string, config QueryConfig) (map[string]string, int) {
	// retrievedCerts is the bytes of a certificate mapped to the
	// ID, issuer name, and before/after values.
	retrievedCerts := make(map[string]string)

	// biggestID is the most recent certificate id returned from CertSpotter.

	// timeToWait is the amount of time you need to wait before querying again.
	var biggestID, timeToWait int

	// retryAfter is the timeToWait value from the response headers.
	var retryAfter string

	// If the caddyCertsSANs is empty, it shouldn't run this at all.
	for _, domainName := range caddyCertsSANs {
		retryAfter = queryDomainName(domainName, config, &biggestID, retrievedCerts)
	}
	err := putLatestID(biggestID, filePath)
	if err != nil {
		//return fmt.Errorf("writing latest ID: %v", err)
		log.Printf("[WARNING] writing latest ID (%v): %v", biggestID, err)
	}
	timeToWait, err = strconv.Atoi(retryAfter)
	if err != nil {
		log.Printf(err.Error())
		log.Print("Error retrieving time to wait, waiting 1 hour\n")
		timeToWait = 3600
	}
	// returning retrievedCerts because it is created here and timeToWait
	// so that I wait enough time before trying again.
	return retrievedCerts, timeToWait
}

// monitorCerts continuously monitors the certificates that Caddy serves,
// it queries again after the specified time.
func monitorCerts() {
	var queryConfig QueryConfig
	config := loadConfig()
	for {
		namesToLookUp, caddyCerts := getCaddyCerts()
		if len(namesToLookUp) == 0 {
			log.Print("Could not retrieve DNS names from Caddy Certificate\n" +
				"Make sure that you are serving on port 80 & 443\n" +
				"Terminating monitorCerts.")
			break
		}
		startingIndex, err := getLatestIndex(filePath)
		if err != nil {
			log.Printf("Error %v while getting starting index, starting at 0", err)
		}
		queryConfig.Subdomains = config.IncludeSubdomains
		queryConfig.WildCards = config.IncludeWildCards
		queryConfig.Query = certSpotterAPIBase
		queryConfig.Index = startingIndex
		fetchedCerts, pause := lookUpNames(namesToLookUp, queryConfig)
		CompareCerts(caddyCerts, fetchedCerts)
		time.Sleep(time.Duration(pause) * time.Second)
	}
}

func prepQuery(domainName string, config QueryConfig) (query string) {
	v := url.Values{}
	v.Set("domain", domainName)
	if config.WildCards {
		v.Set("match_wildcards", "true")
	}
	if config.Subdomains {
		v.Set("include_subdomains", "true")
	}
	v.Set("after", strconv.Itoa(config.Index))
	v.Add("expand", "dns_names")
	v.Add("expand", "issuer")
	v.Add("expand", "cert")
	encodedValue := v.Encode()
	query = config.Query + "?" + encodedValue
	return query
}

func putLatestID(currentID int, fileName string) error {
	writeValue := strconv.Itoa(currentID)
	return ioutil.WriteFile(fileName, []byte(writeValue), 0600)
}

func queryDomainName(domainName string, config QueryConfig, biggestID *int, retrievedCerts map[string]string) string {
	var (
		querySize  int
		retryAfter string
	)

	for ok := true; ok; ok = querySize > 0 {
		querySize, config.Index, retryAfter = getCertSpotterCerts(domainName, config, biggestID, retrievedCerts)
	}
	return retryAfter
}

func startMonitoring(eventType caddy.EventName, eventInfo interface{}) error {
	go monitorCerts()
	return nil
}

func getCertSpotterCerts(domainName string, config QueryConfig, biggestID *int, retrievedCerts map[string]string) (numOfIssuanceObjects int, issuanceID int, retryAfter string) {
	// issuanceObjects consists of the issuanceObjects returned from CertSpotter.
	issuanceID = config.Index
	var (
		issuanceObjects []CertSpotterResponse
		certQuery       string
	)
	certQuery = prepQuery(domainName, config)

	response, err := http.Get(certQuery)
	if err != nil {
		log.Printf("https get request failed on input %s \nError: %v", prepQuery(domainName, config), err)
	}
	defer response.Body.Close()

	err = json.NewDecoder(response.Body).Decode(&issuanceObjects) // handle error
	if err != nil {
		//return fmt.Errorf("decoding json stream: %v", err)
		log.Printf("[WARNING] error decoding json stream: %v", err)
	}

	numOfIssuanceObjects = len(issuanceObjects)
	fmt.Printf("Length of issuanceObjects: %v\n", numOfIssuanceObjects)
	if numOfIssuanceObjects > 0 {
		for i, issuance := range issuanceObjects {
			bytes, err := base64.StdEncoding.DecodeString(issuance.Cert.Data)
			if err != nil {
				log.Printf("Decoding failed: %v", err)
			}
			aKey := string(bytes)
			if _, ok := retrievedCerts[aKey]; ok {
				continue
			}
			if issuance.Cert.Type == "precert" {
				continue
			}
			value := "ID: " + issuance.Cert.ID + " " + issuance.Issuer.Name + " not valid before: " + issuance.NotBefore +
				" and not valid after: " + issuance.NotAfter
			retrievedCerts[aKey] = value
			if i == numOfIssuanceObjects-1 {
				issuanceID, err = strconv.Atoi(issuance.ID)
				if err != nil {
					log.Printf(err.Error())
					log.Print("Error occurred on line 277 of ctmonitor")
				}
				if issuanceID > *biggestID {
					*biggestID = issuanceID
				}
			}
		}
	} else {
		retryAfter = response.Header.Get("Retry-After")
		log.Printf("retryAfter: %v", retryAfter)
	}
	return
}
