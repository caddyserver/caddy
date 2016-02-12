package translate

func init() {
	AddLanguage("es-ES", esES)
}

var esES = map[string]string{
	"Agree to Let's Encrypt Subscriber Agreement": "De acuerdo a Let's Encrypt Acuerdo de suscripción",
	"Certificate authority's ACME server":         "ACME servidor de autoridad de certificación",
	"Error opening process log file: %v":          "Error al abrir el archivo de registro de proceso: %v",
	"Revoked certificate for %s\n":                "Certificado revocado para %s\n",
}
