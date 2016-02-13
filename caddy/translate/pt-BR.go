package translate

func init() {
	AddLanguage("pt-BR", ptBR)
}

var ptBR = map[string]string{
	"Agree to Let's Encrypt Subscriber Agreement": "Concorda com o Acordo de Subscrição do Let's Encrypt",
	"Certificate authority's ACME server":         "Servidor ACME da autoridade de certificação",
	"Error opening process log file: %v":          "Erro ao abrir o arquivo de log do proceso: %v",
	"Revoked certificate for %s\n":                "Certificado revogado para %s\n",
}
