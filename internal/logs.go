package internal

import "fmt"

// MaxSizeSubjectsListForLog returns the keys in the map as a slice of maximum length
// maxToDisplay. It is useful for logging domains being managed, for example, since a
// map is typically needed for quick lookup, but a slice is needed for logging, and this
// can be quite a doozy since there may be a huge amount (hundreds of thousands).
func MaxSizeSubjectsListForLog(subjects map[string]struct{}, maxToDisplay int) []string {
	numberOfNamesToDisplay := min(len(subjects), maxToDisplay)
	domainsToDisplay := make([]string, 0, numberOfNamesToDisplay)
	for domain := range subjects {
		domainsToDisplay = append(domainsToDisplay, domain)
		if len(domainsToDisplay) >= numberOfNamesToDisplay {
			break
		}
	}
	if len(subjects) > maxToDisplay {
		domainsToDisplay = append(domainsToDisplay, fmt.Sprintf("(and %d more...)", len(subjects)-maxToDisplay))
	}
	return domainsToDisplay
}
