package internal

import "fmt"

// MaxSizeSubjectsListForLog returns up to maxToDisplay keys from subjects.
// If any keys are omitted, it appends one additional entry summarising the
// omitted count. This bounds the number of subject names placed in the log
// while making truncation explicit.
func MaxSizeSubjectsListForLog(subjects map[string]struct{}, maxToDisplay int) []string {
	numberOfNamesToDisplay := min(len(subjects), maxToDisplay)
	domainsToDisplay := make([]string, 0, numberOfNamesToDisplay)
	for domain := range subjects {
		if len(domainsToDisplay) >= numberOfNamesToDisplay {
			break
		}
		domainsToDisplay = append(domainsToDisplay, domain)
	}
	if len(subjects) > maxToDisplay {
		domainsToDisplay = append(domainsToDisplay, fmt.Sprintf("(and %d more...)", len(subjects)-maxToDisplay))
	}
	return domainsToDisplay
}
