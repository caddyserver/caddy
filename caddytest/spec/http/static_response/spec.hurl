# Configure Caddy
POST http://localhost:2019/load
User-Agent: hurl/ci
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	log
	respond "Hello, World!"
}
```

GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
`Hello, World!`


GET https://localhost:9443/foo
[Options]
insecure: true
HTTP 200
[Asserts]
`Hello, World!`

# Configure Caddy
POST http://localhost:2019/load
User-Agent: hurl/ci
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	respond "New text!"
}
```

GET https://localhost:9443
[Options]
insecure: true
HTTP/2 200
[Asserts]
`New text!`


GET https://localhost:9443/foo
[Options]
insecure: true
HTTP/2 200
[Asserts]
`New text!`

GET https://localhost:9443/foo
[Options]
insecure: true
HTTP/2 200
[Asserts]
body != "Hello, World!"

# Configure Caddy
# The body is a placeholder
POST http://localhost:2019/load
User-Agent: hurl/ci
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	log
	respond {http.request.body}
}
```

# handler responds with the "application/json" if the response body is valid JSON
POST https://localhost:9443
[Options]
insecure: true
```json
{
	"greeting": "Hello, world!"
}
```
HTTP/2 200
[Asserts]
header "Content-Type" == "application/json"
```json
{
	"greeting": "Hello, world!"
}
```
