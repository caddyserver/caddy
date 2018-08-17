/*I have my program working so far, I need to try to compare certificates from Caddy with the ones I can get from certSpotter and then I need to try the time.Sleep(pause) where pause is the timeToSleep returned from the headers.  If I find and certs that don't match, I want to send those to the user in a way that they would recognize them.*/
//On a side note, the data field in the cert struct is what I want to compare against.
//Maybe instead of the empty struct I should have it be mapped to the issuing CA

package caddytls

import (
	/*"bytes"
	"context" 
	"flag"*/
	"fmt"
	"log"
	"net/http"
	/*"reflect"
	"time"*/
	b64 "encoding/base64"
	"encoding/asn1"
	"encoding/json"	
	"net/url"
	"io/ioutil"
	
	//ct "github.com/google/certificate-transparency-go"
	/*"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"*/
	"github.com/mholt/caddy"
	//"github.com/mholt/caddy/caddytls"//Used for caddytls.Certificate
	"bufio"
	"os"
	//"crypto/sha256"
	"strconv"
	"strings"
	//"reflect"
)

//type Certificate string//TODO remove this once I know what Certificate is.

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


func decodeCert(object SslmateStruct) SslmateStruct {
	cert := object.Cert
	/*cert.ID, err := b64.StdEncoding.DecodeString(cert.ID)
	if err != nil {
		log.Fatalf("Decoding failed: %v", err)
	}
	_, err := asn1.Unmarshal(cert.ID, &cert.ID)
	checkUnmarshalError(err)... //would have done this for each cert field.
	*/
	cert.ID = decodeField(cert.ID)
	cert.Type = decodeField(cert.Type)
	cert.Sha256 = decodeField(cert.Sha256)
	cert.Data = decodeField(cert.Data)
	object.Cert = cert
	return object
}

func decodeField(value string) string {
	//First decode the base64 encoding
	bytes, err := b64.StdEncoding.DecodeString(value)
	if err != nil {
		log.Fatalf("Decoding failed: %v", err)
	}
	checkUnmarshalError(err)
	//Then decode the asn.1 DER encoding to get the fields we are used to using.
	_, err1 := asn1.Unmarshal(bytes, &value)
	checkUnmarshalError(err1)
	return value
}


func checkUnmarshalError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error unmarshaling cert: %s", err.Error())
		os.Exit(1)
	}
}


// GetCaddyCerts retrieves the certificates that caddy monitors and returns them as a map of
// their respective byte arrays casted as a string to the array of SAN
func getCaddyCerts() ([]string, map[string]struct{}) {
	//fmt.Println("Inside getCaddyCerts")
	//var caddyCerts = make(map[string][]Certificate)
	var caddyCerts = make(map[string]struct{})//the string will just be the cert type?
	var caddyDNS = make([]string, 0, 10)
	//fmt.Printf("number of caddy instances: %v\n", len(caddy.Instances()))
	for i, inst := range caddy.Instances() {
		//fmt.Printf("i: %v\n", i)
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		//certCache, ok := inst.Storage["tls_cert_cache"].(*certificateCache)//Get help from Matt in the morning.
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}

		certCache.RLock()
		for _, certificate := range certCache.cache {
			//fmt.Printf("Certificate Bytes: %#v\n", certificate.Certificate.Certificate[0])
			//fmt.Printf("dnsNames: %#v\n", certificate.Names)
			caddyDNS = append(caddyDNS, certificate.Names...) 
			if _, ok := caddyCerts[string(certificate.Certificate.Certificate[0])]; !ok {//Rework this once I can compile and make sure that I am using the right thing as the key.
				caddyCerts[string(certificate.Certificate.Certificate[0])] = struct{}{}
			}
		}
		certCache.RUnlock()
	}
	//fmt.Printf("caddyCert len: %v\n", len(caddyCerts))
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



func lookUpNames(caddyCertSANs []string, query string, subdomains bool, wildcards bool, index int) (map[string]struct{}, int) {//return retrievedCerts and I'm not sure what []string will be...
	//for each name in caddyCertSANs, perform the query by appending the current name and then the options to the query and then add the results to the map. (map so that I can have a set of unique certs.)
	//Probably want to just return the certs themselves and then convert to bytes for lookup so that I can easily compare them and then return the ones that we are not hosting.  Though I will need to check if the certificate is in a form that I can return to the user, I might need to see if I can get which logs the cert is stored in.
	//retrievedCerts := make(map[ct.LogEntry]Q)
	retrievedCerts := make(map[string]struct{})//not sure what type this should be, and I need to fix this method
	var biggestId, timeToWait int
	var retryAfter string
	//var q Q
	for _, domainName := range caddyCertSANs {
		//Maybe start for loop here?
		/*concurrent, err := strconv.Atoi(index)
		check(err)*/
		concurrent := index
		//hasRun := false
		var issuanceObjects []SslmateStruct
		//issuanceObjects := make([]SslmateStruct, 1)
		//fmt.Println("DomainName: ", domainName)
		for ok := true; ok; ok = len(issuanceObjects) > 0 { //do this until the size is 0, then do one more query and get the after field from the header.
			//biggestId, err := strconv.Atoi(index)
			//check(err)
			temp := strconv.Itoa(concurrent)
			//fmt.Printf("Temp = %v\n", temp)
			response, err := http.Get(query + prepQuery(domainName,
					subdomains, wildcards, temp))//return json struct, we will need to iterate over the response to get each certificate that is returned. Also need to check for a query after variable.
			if err != nil {
				log.Fatalf("https get request failed on input %s \nError: %v", prepQuery(domainName, subdomains, wildcards, strconv.Itoa(concurrent)), err)
			}
			defer response.Body.Close()
			//fmt.Println(response.Header)
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Fatalf("reading response body failed, error: %s", err.Error())
			}
			//temp, _ := ioutil.ReadAll(response.Body)
			//fmt.Println("unmarshal-ing the json.")
			if err := json.Unmarshal(body, &issuanceObjects); err != nil {
				fmt.Println("Unmarshal failed on line 178")
				fmt.Printf("\n\n%#v\n\n", body)
				fmt.Printf("%#v\n", err.Error())
				//panic(err)
				
			}
			//fmt.Printf("%#v\n", issuanceObjects)
			//fmt.Printf("size of response: %v\n", len(issuanceObjects))
			//fmt.Println("issuanceObjects size: %v", len(issuanceObjects))
			if len(issuanceObjects) > 0 {
				for i, issuance := range issuanceObjects {
					fmt.Printf("Issuance Data: %#v\n", issuance.Data)
					/*h := sha256.New()
					//aKey := h.Write(issuance.Cert) //this didn't work, ask matt
					//aKey := h.Write([]byte(issuance.Cert.Data))
					//sha := h.Sum(nil)
					//aKey := h.Write([]byte(issuance.Cert.Data))
					_, err := h.Write([]byte(issuance.Cert.Data))//theBytes is an int, aKey is an error
					if err != nil {
						log.Fatalf("Hashing data failed, err: %v.", err)
					}
					aKey := string(h.Sum(nil))*/
					aKey := issuance.Cert.Data
					//if this doesn't work, then I will just store data as a string
					if _, ok := retrievedCerts[aKey]; ok {
						continue
					} else {//adds only unique certs to my set.
						retrievedCerts[aKey] = struct{}{}
					}
					if i == (len(issuanceObjects) - 1) {
						issuanceId, err := strconv.Atoi(issuance.ID)
						check(err)
						if issuanceId > biggestId {
							biggestId = issuanceId
						}
						concurrent = issuanceId
					}
					//fmt.Println("\n\nFinished query, will try again.\n")
				}
			} else {
				//do query again.  Does encode clear the values of v?
				//fmt.Println("Else Branch")
				finalResponse, err := http.Get(query + prepQuery(domainName,
					subdomains, wildcards, strconv.Itoa(concurrent)))//return json struct, we will need to iterate over the response to get each certificate that is returned. Also need to check for a query after variable.
				if err != nil {
					log.Fatalf("https get request failed on input %s \nError: %v", prepQuery(domainName, subdomains, wildcards, strconv.Itoa(concurrent)), err)
				}
				defer finalResponse.Body.Close()
				//fmt.Println(finalResponse.Header)//printing the final query headers to try to get the retry after value.
				retryAfter = finalResponse.Header.Get("Retry-After")
				
				
			}
			//fmt.Println("Leaving for loop")
		}
		//end for, do check the waiting headers...
	}
	//could do the waiting process time here

//	err := ioutil.WriteFile("./latestCert.txt", []byte(string(0x30)), 0600)
	//err := ioutil.WriteFile("./latestCert.txt", []byte(string(biggestId)), 0600)
	//check(err)
	//return []string, retrievedCerts
	putLatestId(biggestId, FILE_PATH)//Not sure why this isn't working...
	//putLatestId(biggestId, "./latestCert.txt")
	timeToWait, err := strconv.Atoi(retryAfter)
	check(err)
	return retrievedCerts, timeToWait//Maybe also return the amount of time we are supposed to wait here, and have the program wait outside of the loop.
}

func prepQuery(domainName string, subdomains bool, wildcards bool, index string) string {
	v:= url.Values{}//Issue seems to be that when I use this function, it adds a colon to the end? //TODO
	//fmt.Printf("line 188v: %v", v)
	v.Set("domain", domainName)
	if wildcards {
		v.Set("match_wildcards", "true")
	}
	if subdomains {
		v.Set("include_subdomains", "true")
	}
	//lookupValue := strconv.Itoa(concurrent)
	v.Set("after", index)
	v.Add("expand", "dns_names")//Use set if it is unique, and use add if it is replicable.
	v.Add("expand", "issuer")
	v.Add("expand", "cert")
	encodedValue := v.Encode()
	
	//fmt.Println("EncodedValue = ", encodedValue)
	return encodedValue
}


func putLatestId(currentId int, fileName string) {
	fileHandle, err := os.Create(fileName)
	check(err)//log.fatal("could not write to %v", fileName)
	writer := bufio.NewWriter(fileHandle)
	//defer fileHandle.Close()
	writeValue := strconv.Itoa(currentId)
	fmt.Fprintln(writer, writeValue)
	writer.Flush()
	//fileHandle.Close()
}
	
const (
	BASE_URI string = "https://api.certspotter.com/v1/issuances?"
	FILE_PATH string = "./latestCert.txt"
)

//I think I'm at the point that I can work on the waiting time. Maybe do a for over main, and have the waiting time after the call to putLatestId.

func init() {
	fmt.Println("Waiting to start, cleanct.go init")
	caddy.RegisterEventHook("ctmonitor", startMonitoring)
	//go monitorCerts()
}

func startMonitoring(eventType caddy.EventName, eventInfo interface{}) error {
	fmt.Println("StartMonitoring called")
	go monitorCerts()
	return nil
}

func monitorCerts() {
	fmt.Println("Starting monitorCerts")
	//Maybe have a way of checking if the file is not found, then create it with value 0
	//filePath := "./latestCert.txt"
	/*index, err := ioutil.ReadFile(FILE_PATH)
	//fmt.Println(reflect.TypeOf(err))
	if os.IsNotExist(err) {/*
		//Create the file, write a 0, close and try to reopen the file?
		startingValue := make([]byte, 1)
		//startingValue[0] = 1//Figure this out and then I'm good here.
		aVal := "0"
		index = []byte(aVal)
		
		index = startingValue* /
		putLatestId(0, FILE_PATH)
		fmt.Printf("Could not find file at path: %v\nCreating file now.\n", FILE_PATH)
		index1, err1 := ioutil.ReadFile(FILE_PATH)
		//fmt.Println(reflect.TypeOf(err1))
		if err1 != nil {
			log.Fatalf(err1.Error())
		}
		index = index1
		
	} else if err != nil {
		log.Fatalf(err.Error())
	}
	//check(err)
	startingIndex := strings.TrimSpace(string(index))*/
	//fmt.Printf("startingIndex: %v", startingIndex)
	namesToLookUp, caddyCerts := getCaddyCerts()//caddyCerts is a map of bytes to empty struct.
	caddyCerts = caddyCerts
	startingIndex, err := getLatestIndex(FILE_PATH)
	startingIndex = startingIndex
	if err != nil {
		log.Printf("Error %v while getting starting index, starting at 0", err.Error())
	}
	//fmt.Println("length of namesToLookUp: ", len(namesToLookUp))
	if len(namesToLookUp) == 0  {
		namesToLookUp = []string{"gocyrus.net"}
	}
	//fetchedCerts, pause := lookUpNames(namesToLookUp, BASE_URI, false, false, 0)
	fetchedCerts, pause := lookUpNames(namesToLookUp, BASE_URI, false, false, startingIndex)
	//fmt.Println(pause)
	pause = pause
	fetchedCerts = fetchedCerts
	compareCerts(caddyCerts, fetchedCerts)
	/*recordedIndex, err := strconv.Atoi(startingIndex)
	check(err)*/
	//putLatestId(, FILE_PATH)
}

func compareCerts(caddyCerts map[string]struct{}, fetchedCerts map[string]struct{}) {
	found := false
	enteredLoop := false
	for key := range caddyCerts {//go through each cert in caddy, if I can find it in the fetched certs (matching keys) then I know that the keys are the right type.
		enteredLoop = true
		fmt.Printf("caddy key: %v\n", key)
		if _, ok := fetchedCerts[key]; ok {
			found = true
		} else {//adds only unique certs to my set.
			continue
		}
	}
	if found {
		fmt.Println("Found a matching cert")
	} else {
		fmt.Println("Encodings are off, try again")
	}
	if enteredLoop {
		fmt.Printf("entered loop, len of caddyCerts: %v\n", len(caddyCerts))
	} else {
		fmt.Printf("Len of caddyCerts: %v, didn't enter loop\n", len(caddyCerts))
	}
}
	


func check(e error) {
	if e != nil {
		//log.Fatalf(e)
		log.Fatalf(e.Error())
		
	}
}
