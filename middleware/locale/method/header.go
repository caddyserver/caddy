package method

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func detectByHeader(r *http.Request, _ *Configuration) []string {
	browserLocales := parseBrowserLocales(r.Header.Get("Accept-Language"))
	sort.Sort(browserLocales)
	return browserLocales.locales()
}

type browserLocales []*browserLocale

func parseBrowserLocales(text string) browserLocales {
	browserLocales := browserLocales{}

	for _, part := range strings.Split(text, ",") {
		part := strings.TrimSpace(part)
		if part == "" {
			continue
		}
		browserLocales = append(browserLocales, parseBrowserLocale(part))
	}

	return browserLocales
}

func (bl browserLocales) Len() int {
	return len(bl)
}

func (bl browserLocales) Less(i, j int) bool {
	return bl[i].q > bl[j].q
}

func (bl browserLocales) Swap(i, j int) {
	bl[i], bl[j] = bl[j], bl[i]
}

func (bl browserLocales) locales() []string {
	result := make([]string, len(bl))
	for index, browserLocale := range bl {
		result[index] = browserLocale.locale
	}
	return result
}

type browserLocale struct {
	locale string
	q      float64
}

func parseBrowserLocale(text string) *browserLocale {
	parts := strings.Split(text, ";")

	browserLocale := &browserLocale{
		locale: strings.TrimSpace(parts[0]),
		q:      1.0,
	}
	if len(parts) > 1 {
		if values, err := url.ParseQuery(strings.TrimSpace(parts[1])); err == nil {
			if qValue := values.Get("q"); qValue != "" {
				if q, err := strconv.ParseFloat(qValue, 64); err == nil {
					browserLocale.q = q
				}
			}
		}
	}

	return browserLocale
}
