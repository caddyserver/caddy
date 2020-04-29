package caddyhttp

var PlaceholderShorthands = []string{
	"dir", "http.request.uri.path.dir",
	"file", "http.request.uri.path.file",
	"host", "http.request.host",
	"hostport", "http.request.hostport",
	"method", "http.request.method",
	"path", "http.request.uri.path",
	"query", "http.request.uri.query",
	"remote", "http.request.remote",
	"remote_host", "http.request.remote.host",
	"remote_port", "http.request.remote.port",
	"scheme", "http.request.scheme",
	"uri", "http.request.uri",
	"tls_cipher", "http.request.tls.cipher_suite",
	"tls_version", "http.request.tls.version",
	"tls_client_fingerprint", "http.request.tls.client.fingerprint",
	"tls_client_issuer", "http.request.tls.client.issuer",
	"tls_client_serial", "http.request.tls.client.serial",
	"tls_client_subject", "http.request.tls.client.subject",
}

var PlaceholderShorthandsWithBraces []string

func init() {
	for _, value := range PlaceholderShorthands {
		PlaceholderShorthandsWithBraces = append(PlaceholderShorthandsWithBraces, "{"+value+"}")
	}
}
