package push

import (
	"strings"
)

const (
	commaSeparator     = ","
	semicolonSeparator = ";"
	equalSeparator     = "="
)

type linkResource struct {
	uri    string
	params map[string]string
}

// parseLinkHeader is responsible for parsing Link header and returning list of found resources.
//
// Accepted formats are:
// Link: </resource>; as=script
// Link: </resource>; as=script,</resource2>; as=style
// Link: </resource>;</resource2>
func parseLinkHeader(header string) []linkResource {
	resources := []linkResource{}

	if header == "" {
		return resources
	}

	for _, link := range strings.Split(header, commaSeparator) {
		l := linkResource{params: make(map[string]string)}

		li, ri := strings.Index(link, "<"), strings.Index(link, ">")

		if li == -1 || ri == -1 {
			continue
		}

		l.uri = strings.TrimSpace(link[li+1 : ri])

		for _, param := range strings.Split(strings.TrimSpace(link[ri+1:]), semicolonSeparator) {
			parts := strings.SplitN(strings.TrimSpace(param), equalSeparator, 2)
			key := strings.TrimSpace(parts[0])

			if key == "" {
				continue
			}

			if len(parts) == 1 {
				l.params[key] = key
			}

			if len(parts) == 2 {
				l.params[key] = strings.TrimSpace(parts[1])
			}
		}

		resources = append(resources, l)
	}

	return resources
}
