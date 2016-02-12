package translate

import "strings"

// LanguageSet is a map of string IDs to the translated string.
// It is common for the string ID to be an actual string in the
// 'default' language (usually English) rather than a contrived
// ID, as it preserves context when it appears in the program.
type LanguageSet map[string]string

// locale is the BCP 47 code of the current language.
var locale = "en-US"

// translations maps BCP 47 language codes to the
// set of strings that belong to that language.
var translations = make(map[string]LanguageSet)

// AddLanguage maps a BCP 47 code to its language set.
func AddLanguage(bcp47 string, set LanguageSet) {
	translations[strings.ToLower(bcp47)] = set
}

// SetLocale configures this package to use the language
// set keyed by the bcp47 code.
func SetLocale(bcp47 string) {
	locale = strings.ToLower(bcp47)
}

// GetLocale returns the current locale.
func GetLocale(bcp47 string) string {
	return locale
}

// Text returns the string keyed by id in the language
// according to the current locale.
func Text(id string) string {
	languageDB, ok := translations[locale]
	if !ok {
		return id
	}
	translation, ok := languageDB[id]
	if !ok {
		return id
	}
	return translation
}
