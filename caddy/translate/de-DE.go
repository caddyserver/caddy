package translate

func init() {
	AddLanguage("de-DE", deDE)
}

var deDE = map[string]string{
	"Agree to Let's Encrypt Subscriber Agreement": "Stimme der Let's Encrypt Abonnenten-Vereinbarung zu",
	"Certificate authority's ACME server":         "ACME-Server der Zertifizierungsstelle",
	"Error opening process log file: %v":          "Fehler beim Öffnern der Prozess-Logdatei: %v",
	"Revoked certificate for %s\n":                "Zertifikat zurückziehen für %s\n",
}
