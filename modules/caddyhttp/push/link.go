// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package push

import (
	"strings"
)

// linkResource contains the results of a parsed Link header.
type linkResource struct {
	uri    string
	noPush bool
}

func parseLinkHeader(header string) []linkResource {
	resources := []linkResource{}

	for len(header) > 0 {
		var link string
		idx := strings.IndexByte(header, ',')
		if idx >= 0 {
			link = header[:idx]
			header = header[idx+1:]
		} else {
			link = header
			header = ""
		}

		li, ri := strings.IndexByte(link, '<'), strings.IndexByte(link, '>')
		if li == -1 || ri == -1 {
			continue
		}

		l := linkResource{
			uri: strings.TrimSpace(link[li+1 : ri]),
		}

		paramsPart := strings.TrimSpace(link[ri+1:])
		for len(paramsPart) > 0 {
			var param string
			pidx := strings.IndexByte(paramsPart, ';')
			if pidx >= 0 {
				param = paramsPart[:pidx]
				paramsPart = paramsPart[pidx+1:]
			} else {
				param = paramsPart
				paramsPart = ""
			}

			before, _, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.TrimSpace(before) == "nopush" {
				l.noPush = true
				break
			}
		}

		resources = append(resources, l)
	}

	return resources
}
