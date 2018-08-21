package caddytls

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mholt/caddy"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	BASE_URI string = "https://api.certspotter.com/v1/issuances?"
	FILE_PATH string = "./latestCert.txt"
)

// SslmateStruct is the json response formatting that is used in the program.
type SslmateStruct struct { 
	ID           string   `json:"id"`
	TbsSha256    string   `json:"tbs_sha256"`
	DNSNames     []string `json:"dns_names"`
	PubkeySha256 string   `json:"pubkey_sha256"`
	Issuer       struct {
		Name         string `json:"name"`
		PubkeySha256 string `json:"pubkey_sha256"`
	} `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Cert      struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Sha256 string `json:"sha256"`
		Data   string `json:"data"`
	} `json:"cert"`
}

func check(e error) {
	if e != nil {
		log.Printf(e.Error())
	}
}

// compareCerts compares the certificates that caddy is serving against the certificates
// that certSpotter has found, if there are any that don't match the caddy certificates,
// they are reported to the user.
func compareCerts(caddyCerts map[string]struct{}, certSpotterCerts map[string]string) {
	for key := range certSpotterCerts {
		if _, ok := caddyCerts[key]; ok {
			continue
		} else {
			log.Printf("[WARNING] Certificate found that caddy is not monitoring, issued by: %v\n", certSpotterCerts[key])
			fmt.Printf("[WARNING] Certificate found that caddy is not monitoring, issued by: %v\n", certSpotterCerts[key])
		}
	}
}

func decodeField(value string) []byte {
	bytes, err := b64.StdEncoding.DecodeString(value)
	if err != nil {
		log.Fatalf("Decoding failed: %v", err)
	}
	return bytes
}

// getCaddyCerts retrieves the certificates that caddy monitors and returns them as a map
// with the key being the bytes of the certificate cast to a string.
func getCaddyCerts() ([]string, map[string]struct{}) {
	var caddyCerts = make(map[string]struct{})
	var caddyDNS = make([]string, 0, 10)
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
			if _, ok := caddyCerts[string(certificate.Certificate.Certificate[0])]; !ok {
				caddyCerts[string(certificate.Certificate.Certificate[0])] = struct{}{}
			}
		}
		certCache.RUnlock()
	}
	return caddyDNS, caddyCerts
}

func getLatestIndex(fileName string) (int, error) {
	indexBytes, err := ioutil.ReadFile(fileName)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	indexStr := strings.TrimSpace(string(indexBytes))
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		return 0, err
	}
	return index, nil
}

func init() {
	caddy.RegisterEventHook("ctmonitor", startMonitoring)
}

// lookUpNames queries the certSpotter service for each Subject Alternate Name (SAN) that Caddy is hosting certificates
// for.  It then adds them to a set and returns a map of each certificate returned mapped to a string that contains the
// before/after dates for the certificate, as well as the issuing authority.
func lookUpNames(caddyCertSANs []string, query string, subdomains bool, wildcards bool, index int) (map[string]string, int) {
	retrievedCerts := make(map[string]string)
	var biggestId, timeToWait int
	var retryAfter string
	for _, domainName := range caddyCertSANs {
		concurrent := index
		var issuanceObjects []SslmateStruct
		for ok := true; ok; ok = len(issuanceObjects) > 0 {
			temp := strconv.Itoa(concurrent)
			response, err := http.Get(query + prepQuery(domainName,
					subdomains, wildcards, temp))
			if err != nil {
				log.Printf("https get request failed on input %s \nError: %v", prepQuery(domainName, subdomains, wildcards, strconv.Itoa(concurrent)), err)
			}
			defer response.Body.Close()
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Printf("reading response body failed, error: %s", err.Error())
			}
			if err := json.Unmarshal(body, &issuanceObjects); err != nil {
				log.Println("Unmarshal failed on line 178")
				log.Printf("\n\n%#v\n\n", body)
				log.Printf("%#v\n", err.Error())
			}
			if len(issuanceObjects) > 0 {
				for i, issuance := range issuanceObjects {
					bytes := decodeField(issuance.Cert.Data)
					aKey := string(bytes)
					if _, ok := retrievedCerts[aKey]; ok {
						continue
					} else {
						if issuance.Cert.Type == "precert" {
							continue
						}
						value := "ID: " + issuance.Cert.ID + " " + issuance.Issuer.Name + " not valid before: " + issuance.NotBefore +
							" and not valid after: " + issuance.NotAfter
						retrievedCerts[aKey] = value
					}
					if i == (len(issuanceObjects) - 1) {
						issuanceId, err := strconv.Atoi(issuance.ID)
						check(err)
						if issuanceId > biggestId {
							biggestId = issuanceId
						}
						concurrent = issuanceId
					}
				}
			} else {
				finalResponse, err := http.Get(query + prepQuery(domainName,
					subdomains, wildcards, strconv.Itoa(concurrent)))
				if err != nil {
					log.Fatalf("https get request failed on input %s \nError: %v", prepQuery(domainName, subdomains, wildcards, strconv.Itoa(concurrent)), err)
				}
				defer finalResponse.Body.Close()
				retryAfter = finalResponse.Header.Get("Retry-After")	
			}
		}
	}
	putLatestId(biggestId, FILE_PATH)
	timeToWait, err := strconv.Atoi(retryAfter)
	check(err)
	return retrievedCerts, timeToWait
}

// monitorCerts continuously monitors the certificates that Caddy serves. monitorCerts queries again
// after the specified time.
func monitorCerts() {
	pause := 0
	var fetchedCerts map[string]string
	for {
		time.Sleep(time.Duration(pause) * time.Second)
		namesToLookUp, caddyCerts := getCaddyCerts()
		startingIndex, err := getLatestIndex(FILE_PATH)
		if err != nil {
			log.Printf("Error %v while getting starting index, starting at 0", err.Error())
		}
		fetchedCerts, pause = lookUpNames(namesToLookUp, BASE_URI, false, false, startingIndex)
		compareCerts(caddyCerts, fetchedCerts)
	}
}

func prepQuery(domainName string, subdomains bool, wildcards bool, index string) string {
	v:= url.Values{}
	v.Set("domain", domainName)
	if wildcards {
		v.Set("match_wildcards", "true")
	}
	if subdomains {
		v.Set("include_subdomains", "true")
	}
	v.Set("after", index)
	v.Add("expand", "dns_names")
	v.Add("expand", "issuer")
	v.Add("expand", "cert")
	encodedValue := v.Encode()
	
	return encodedValue
}

func putLatestId(currentId int, fileName string) {
	fileHandle, err := os.Create(fileName)
	if err != nil {
		log.Printf("[ERROR] could not write to %v", fileName)
	}
	writer := bufio.NewWriter(fileHandle)
	defer fileHandle.Close()
	writeValue := strconv.Itoa(currentId)
	fmt.Fprintln(writer, writeValue)
	writer.Flush()
}

func startMonitoring(eventType caddy.EventName, eventInfo interface{}) error {
	go monitorCerts()
	return nil
}



