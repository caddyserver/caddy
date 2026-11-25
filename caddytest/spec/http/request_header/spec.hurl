# Configure Caddy with request_header directive
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	request_header X-Custom-Header "CustomValue"
	respond "{header.X-Custom-Header}"
}
```

# request_header adds headers to request
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "CustomValue"


# Configure Caddy with request_header removing headers
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	request_header -User-Agent
	respond "UA: {header.User-Agent}"
}
```

# request_header can remove headers
GET https://localhost:9443
User-Agent: TestAgent/1.0
[Options]
insecure: true
HTTP 200
[Asserts]
body == "UA: "


# Configure Caddy with request_header replacing headers
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	request_header Host "example.com"
	respond "Host: {host}"
}
```

# request_header can replace Host header
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Host: example.com"


# Configure Caddy with request_header using placeholders
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	request_header X-Original-Path {path}
	respond "Path: {header.X-Original-Path}"
}
```

# request_header can use placeholders
GET https://localhost:9443/test/path
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Path: /test/path"


# Configure Caddy with conditional request_header
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	@api path /api/*
	request_header @api X-API "true"
	respond "API: {header.X-API}"
}
```

# request_header applies conditionally based on matcher
GET https://localhost:9443/api/test
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API: true"


# request_header doesn't apply when matcher doesn't match
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API: "


# Configure Caddy with multiple request_header operations
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	request_header X-First "1"
	request_header X-Second "2"
	request_header X-Third "3"
	respond "{header.X-First},{header.X-Second},{header.X-Third}"
}
```

# multiple request_header directives are applied
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "1,2,3"


# Configure Caddy with request_header and reverse_proxy
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
	request_header X-Custom-Header "Value"
	reverse_proxy localhost:9450
}
http://localhost:9450 {
	respond "{header.X-Custom-Header}"
}
```

# request_header adds header before reverse_proxy
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Value"
