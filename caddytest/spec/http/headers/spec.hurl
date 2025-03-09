# Configure Caddy
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
	debug
}
localhost {
	header "X-Custom-Header" "Custom-Value"
}
```

GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Custom-Header" == "Custom-Value"
