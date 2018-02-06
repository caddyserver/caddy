package transformrequest

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type DynamoFunc struct{}

func (f DynamoFunc) Transform(r *http.Request) (*http.Request, error) {
	var routeExp = regexp.MustCompile(`ids/v1/([0-9a-z]+)/([0-9a-z\-\_\.]+)/([0-9A-Za-z]+)`)
	match := routeExp.FindStringSubmatch(r.RequestURI)

	result := make(map[string]string)
	for i, name := range routeExp.SubexpNames() {
		if i != 0 {
			result[name] = match[i]
		}
	}
	// entitytype := match[1]
	domain := match[2]
	id := match[3]

	// cid is the client (i.e. tenant) id. It is hardcoded here, but will be extracted from the security context
	// the security context is the information about the current user, their role and scope of access for the
	// current session etc.
	cid := "c016"

	r.ParseForm()
	params := r.Form

	var sortKeys []string
	var partitionKeys []string
	var paramErrors []string

	pkv := "cid=" + cid + ",spid=" + domain + ",suu=" + id
	partitionKeys = []string{pkv}

	for k, v := range params {
		switch k {
		case "targets":
			for _, p := range v {
				for _, target := range strings.Split(p, ",") {
					sortKeys = append(sortKeys, "dpid="+target)
				}
			}
		case "values":
		case "backend":
		default:
			paramErrors = append(paramErrors, fmt.Sprintf("Unknown query parameter: %s\n", k))
		}
	}

	if len(paramErrors) != 0 {
		responseError := strings.Join(paramErrors, "")
		return r, errors.New("Bad Request: " + responseError)
	}

	r.Form["partitionkeys"] = partitionKeys
	r.Form["sortkeys"] = sortKeys

	return r, nil
}
