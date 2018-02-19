package syntax

import (
	"strconv"
	"strings"
)

// `tls:"head=2,min=2,max=255,varint"`

type tagOptions map[string]uint

var (
	varintOption = "varint"

	headOptionNone   = "none"
	headOptionVarint = "varint"
	headValueNoHead  = uint(255)
	headValueVarint  = uint(254)
)

// parseTag parses a struct field's "tls" tag as a comma-separated list of
// name=value pairs, where the values MUST be unsigned integers, or in
// the special case of head, "none" or "varint"
func parseTag(tag string) tagOptions {
	opts := tagOptions{}
	for _, token := range strings.Split(tag, ",") {
		if token == varintOption {
			opts[varintOption] = 1
			continue
		}

		parts := strings.Split(token, "=")
		if len(parts[0]) == 0 {
			continue
		}

		if len(parts) == 1 {
			continue
		}

		if parts[0] == "head" && parts[1] == headOptionNone {
			opts[parts[0]] = headValueNoHead
		} else if parts[0] == "head" && parts[1] == headOptionVarint {
			opts[parts[0]] = headValueVarint
		} else if val, err := strconv.Atoi(parts[1]); err == nil && val >= 0 {
			opts[parts[0]] = uint(val)
		}
	}
	return opts
}
