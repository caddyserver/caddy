// The route53 package provides types and functions for interaction with the AWS
// Route53 service
package route53

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/goamz/aws"
)

// The Route53 type encapsulates operations operations with the route53 endpoint.
type Route53 struct {
	aws.Auth
	aws.Region
	httpClient *http.Client
}

const APIVersion = "2013-04-01"

// New creates a new ELB instance.
func New(auth aws.Auth, region aws.Region) *Route53 {
	return NewWithClient(auth, region, aws.RetryingClient)
}

func NewWithClient(auth aws.Auth, region aws.Region, httpClient *http.Client) *Route53 {
	return &Route53{auth, region, httpClient}
}

type CreateHostedZoneRequest struct {
	Name            string `xml:"Name"`
	CallerReference string `xml:"CallerReference"`
	Comment         string `xml:"HostedZoneConfig>Comment"`
}

type CreateHostedZoneResponse struct {
	HostedZone    HostedZone    `xml:"HostedZone"`
	ChangeInfo    ChangeInfo    `xml:"ChangeInfo"`
	DelegationSet DelegationSet `xml:"DelegationSet"`
}

type HostedZone struct {
	ID              string `xml:"Id"`
	Name            string `xml:"Name"`
	CallerReference string `xml:"CallerReference"`
	Comment         string `xml:"Config>Comment"`
	ResourceCount   int    `xml:"ResourceRecordSetCount"`
}

type ChangeInfo struct {
	ID          string `xml:"Id"`
	Status      string `xml:"Status"`
	SubmittedAt string `xml:"SubmittedAt"`
}

type DelegationSet struct {
	NameServers []string `xml:"NameServers>NameServer"`
}

func (r *Route53) query(method, path string, req, resp interface{}) error {
	params := make(map[string]string)
	endpoint, err := url.Parse(r.Region.Route53Endpoint)
	if err != nil {
		return err
	}
	endpoint.Path = path
	sign(r.Auth, endpoint.Path, params)

	// If they look like url.Values, just encode...
	if queryArgs, ok := req.(url.Values); ok {
		endpoint.RawQuery = queryArgs.Encode()
		req = nil
	}

	// Encode the body
	var body io.ReadWriter
	if req != nil {
		bodyBuf := bytes.NewBuffer(nil)
		enc := xml.NewEncoder(bodyBuf)
		start := xml.StartElement{
			Name: xml.Name{
				Space: "",
				Local: reflect.Indirect(reflect.ValueOf(req)).Type().Name(),
			},
			Attr: []xml.Attr{{xml.Name{"", "xmlns"}, "https://route53.amazonaws.com/doc/2013-04-01/"}},
		}
		if err := enc.EncodeElement(req, start); err != nil {
			return err
		}

		// This is really a sadness, but can't think of a better way to
		// do this for now in Go's constructs.
		replace := "<ResourceRecords><ResourceRecord></ResourceRecord></ResourceRecords>"
		if strings.Contains(bodyBuf.String(), replace) {
			var newBuf bytes.Buffer
			newBuf.WriteString(strings.Replace(bodyBuf.String(), replace, "", -1))
			bodyBuf = &newBuf
		}

		// http://docs.aws.amazon.com/Route53/latest/APIReference/CreateAliasRRSAPI.html
		if reflect.Indirect(reflect.ValueOf(req)).Type().Name() == "ChangeResourceRecordSetsRequest" {
			for _, change := range req.(ChangeResourceRecordSetsRequest).Changes {
				if change.Record.AliasTarget != nil {
					replace := change.Record.Type + "</Type><TTL>0</TTL>"
					var newBuf bytes.Buffer
					newBuf.WriteString(strings.Replace(bodyBuf.String(), replace, change.Record.Type+"</Type>", -1))
					bodyBuf = &newBuf
				}
			}
		}

		body = bodyBuf
	}

	// Make the http request
	hReq, err := http.NewRequest(method, endpoint.String(), body)
	if err != nil {
		return err
	}
	for k, v := range params {
		hReq.Header.Set(k, v)
	}
	re, err := r.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer re.Body.Close()

	// Check the status code
	switch re.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, re.Body)
		return fmt.Errorf("Request failed, got status code: %d. Response: %s",
			re.StatusCode, body.Bytes())
	}

	// Decode the response
	decoder := xml.NewDecoder(re.Body)
	return decoder.Decode(resp)
}

func multimap(p map[string]string) url.Values {
	q := make(url.Values, len(p))
	for k, v := range p {
		q[k] = []string{v}
	}
	return q
}

// CreateHostedZone is used to create a new hosted zone
func (r *Route53) CreateHostedZone(req *CreateHostedZoneRequest) (*CreateHostedZoneResponse, error) {
	// Generate a unique caller reference if none provided
	if req.CallerReference == "" {
		req.CallerReference = time.Now().Format(time.RFC3339Nano)
	}
	out := &CreateHostedZoneResponse{}
	if err := r.query("POST", fmt.Sprintf("/%s/hostedzone", APIVersion), req, out); err != nil {
		return nil, err
	}
	return out, nil
}

type DeleteHostedZoneResponse struct {
	ChangeInfo ChangeInfo `xml:"ChangeInfo"`
}

func (r *Route53) DeleteHostedZone(ID string) (*DeleteHostedZoneResponse, error) {
	// Remove the hostedzone prefix if given
	ID = CleanZoneID(ID)
	out := &DeleteHostedZoneResponse{}
	err := r.query("DELETE", fmt.Sprintf("/%s/hostedzone/%s", APIVersion, ID), nil, out)
	if err != nil {
		return nil, err
	}
	return out, err
}

// CleanZoneID is used to remove the leading /hostedzone/
func CleanZoneID(ID string) string {
	if strings.HasPrefix(ID, "/hostedzone/") {
		ID = strings.TrimPrefix(ID, "/hostedzone/")
	}
	return ID
}

// CleanChangeID is used to remove the leading /change/
func CleanChangeID(ID string) string {
	if strings.HasPrefix(ID, "/change/") {
		ID = strings.TrimPrefix(ID, "/change/")
	}
	return ID
}

type GetHostedZoneResponse struct {
	HostedZone    HostedZone    `xml:"HostedZone"`
	DelegationSet DelegationSet `xml:"DelegationSet"`
}

func (r *Route53) GetHostedZone(ID string) (*GetHostedZoneResponse, error) {
	// Remove the hostedzone prefix if given
	ID = CleanZoneID(ID)
	out := &GetHostedZoneResponse{}
	err := r.query("GET", fmt.Sprintf("/%s/hostedzone/%s", APIVersion, ID), nil, out)
	if err != nil {
		return nil, err
	}
	return out, err
}

type ListHostedZonesResponse struct {
	HostedZones []HostedZone `xml:"HostedZones>HostedZone"`
	Marker      string       `xml:"Marker"`
	IsTruncated bool         `xml:"IsTruncated"`
	NextMarker  string       `xml:"NextMarker"`
	MaxItems    int          `xml:"MaxItems"`
}

func (r *Route53) ListHostedZones(marker string, maxItems int) (*ListHostedZonesResponse, error) {
	values := url.Values{}

	if marker != "" {
		values.Add("marker", marker)
	}

	if maxItems != 0 {
		values.Add("maxItems", strconv.Itoa(maxItems))
	}

	out := &ListHostedZonesResponse{}
	err := r.query("GET", fmt.Sprintf("/%s/hostedzone/", APIVersion), values, out)
	if err != nil {
		return nil, err
	}
	return out, err
}

type GetChangeResponse struct {
	ChangeInfo ChangeInfo `xml:"ChangeInfo"`
}

func (r *Route53) GetChange(ID string) (string, error) {
	ID = CleanChangeID(ID)
	out := &GetChangeResponse{}
	err := r.query("GET", fmt.Sprintf("/%s/change/%s", APIVersion, ID), nil, out)
	if err != nil {
		return "", err
	}
	return out.ChangeInfo.Status, err
}

type ChangeResourceRecordSetsRequest struct {
	Comment string   `xml:"ChangeBatch>Comment,omitempty"`
	Changes []Change `xml:"ChangeBatch>Changes>Change"`
}

type Change struct {
	Action string            `xml:"Action"`
	Record ResourceRecordSet `xml:"ResourceRecordSet"`
}

type AliasTarget struct {
	HostedZoneId         string
	DNSName              string
	EvaluateTargetHealth bool
}

type ChangeResourceRecordSetsResponse struct {
	ChangeInfo ChangeInfo `xml:"ChangeInfo"`
}

func (r *Route53) ChangeResourceRecordSets(zone string,
	req *ChangeResourceRecordSetsRequest) (*ChangeResourceRecordSetsResponse, error) {
	// This is really sad, but we have to format this differently
	// for Route53 to make them happy.
	reqCopy := *req
	for i, change := range reqCopy.Changes {
		if len(change.Record.Records) > 1 {
			var buf bytes.Buffer
			for _, r := range change.Record.Records {
				buf.WriteString(fmt.Sprintf(
					"<ResourceRecord><Value>%s</Value></ResourceRecord>",
					r))
			}

			change.Record.Records = nil
			change.Record.RecordsXML = fmt.Sprintf(
				"<ResourceRecords>%s</ResourceRecords>", buf.String())
			reqCopy.Changes[i] = change
		}
	}

	zone = CleanZoneID(zone)
	out := &ChangeResourceRecordSetsResponse{}
	if err := r.query("POST", fmt.Sprintf("/%s/hostedzone/%s/rrset", APIVersion,
		zone), reqCopy, out); err != nil {
		return nil, err
	}
	return out, nil
}

type ListOpts struct {
	Name       string
	Type       string
	Identifier string
	MaxItems   int
}

type ListResourceRecordSetsResponse struct {
	Records              []ResourceRecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	IsTruncated          bool                `xml:"IsTruncated"`
	MaxItems             int                 `xml:"MaxItems"`
	NextRecordName       string              `xml:"NextRecordName"`
	NextRecordType       string              `xml:"NextRecordType"`
	NextRecordIdentifier string              `xml:"NextRecordIdentifier"`
}

type ResourceRecordSet struct {
	Name          string       `xml:"Name"`
	Type          string       `xml:"Type"`
	TTL           int          `xml:"TTL"`
	Records       []string     `xml:"ResourceRecords>ResourceRecord>Value,omitempty"`
	SetIdentifier string       `xml:"SetIdentifier,omitempty"`
	Weight        int          `xml:"Weight,omitempty"`
	HealthCheckId string       `xml:"HealthCheckId,omitempty"`
	Region        string       `xml:"Region,omitempty"`
	Failover      string       `xml:"Failover,omitempty"`
	AliasTarget   *AliasTarget `xml:"AliasTarget,omitempty"`

	RecordsXML string `xml:",innerxml"`
}

func (r *Route53) ListResourceRecordSets(zone string, lopts *ListOpts) (*ListResourceRecordSetsResponse, error) {
	if lopts == nil {
		lopts = &ListOpts{}
	}
	params := make(map[string]string)
	if lopts.Name != "" {
		params["name"] = lopts.Name
	}
	if lopts.Type != "" {
		params["type"] = lopts.Type
	}
	if lopts.Identifier != "" {
		params["identifier"] = lopts.Identifier
	}
	if lopts.MaxItems != 0 {
		params["maxitems"] = strconv.FormatInt(int64(lopts.MaxItems), 10)
	}

	req := multimap(params)
	zone = CleanZoneID(zone)
	out := &ListResourceRecordSetsResponse{}
	if err := r.query("GET", fmt.Sprintf("/%s/hostedzone/%s/rrset", APIVersion, zone), req, out); err != nil {
		return nil, err
	}
	return out, nil
}

func FQDN(name string) string {
	n := len(name)
	if n == 0 || name[n-1] == '.' {
		return name
	} else {
		return name + "."
	}
}
