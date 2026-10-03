# Configure Caddy with path matcher
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
	respond @api "API endpoint"
	respond "Not API"
}
```

# path matcher matches exact prefix
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API endpoint"


# path matcher doesn't match non-matching paths
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


# Configure Caddy with multiple path patterns
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
	@paths path /api/* /v1/* /v2/*
	respond @paths "Versioned API"
	respond "Other"
}
```

# multiple path patterns match any
GET https://localhost:9443/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Versioned API"


GET https://localhost:9443/v2/posts
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Versioned API"


# Configure Caddy with path_regexp matcher
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
	@uuid path_regexp ^/user/[0-9a-f-]+$
	respond @uuid "User by UUID"
	respond "Other"
}
```

# path_regexp matcher matches regex patterns
GET https://localhost:9443/user/123e4567-e89b-12d3-a456-426614174000
[Options]
insecure: true
HTTP 200
[Asserts]
body == "User by UUID"


# path_regexp doesn't match invalid patterns
GET https://localhost:9443/user/invalid
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other"


# Configure Caddy with header matcher
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
	@api_key header X-API-Key *
	respond @api_key "API access granted"
	respond "No API key"
}
```

# header matcher checks for header presence
GET https://localhost:9443
X-API-Key: secret123
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API access granted"


# header matcher fails without header
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "No API key"


# Configure Caddy with header value matcher
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
	@json header Content-Type application/json
	respond @json "JSON request"
	respond "Other format"
}
```

# header matcher matches exact value
POST https://localhost:9443
Content-Type: application/json
[Options]
insecure: true
```json
{"test": true}
```
HTTP 200
[Asserts]
body == "JSON request"


# header matcher doesn't match different value
POST https://localhost:9443
Content-Type: text/plain
[Options]
insecure: true
```
test
```
HTTP 200
[Asserts]
body == "Other format"


# Configure Caddy with query matcher
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
	@debug query debug=*
	respond @debug "Debug mode"
	respond "Normal mode"
}
```

# query matcher checks for query parameter
GET https://localhost:9443?debug=true
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Debug mode"


# query matcher fails without parameter
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Normal mode"


# Configure Caddy with not matcher
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
	@not_api not path /api/*
	respond @not_api "Not API"
	respond "API"
}
```

# not matcher inverts the match result
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


GET https://localhost:9443/api/test
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API"


# Configure Caddy with multiple matcher conditions (AND logic)
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
	@strict {
		path /api/*
		method POST
		header Content-Type application/json
	}
	respond @strict "Strict match"
	respond "No match"
}
```

# multiple conditions require all to match
POST https://localhost:9443/api/users
Content-Type: application/json
[Options]
insecure: true
```json
{"name": "test"}
```
HTTP 200
[Asserts]
body == "Strict match"


# multiple conditions fail if any doesn't match
POST https://localhost:9443/api/users
Content-Type: text/plain
[Options]
insecure: true
```
test
```
HTTP 200
[Asserts]
body == "No match"
