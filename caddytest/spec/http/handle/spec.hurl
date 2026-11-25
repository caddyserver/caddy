# Configure Caddy with handle directive
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
	handle /api/* {
		respond "API handler"
	}
	handle /static/* {
		respond "Static handler"
	}
	handle {
		respond "Default handler"
	}
}
```

# handle matches first matching path
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API handler"


# handle matches second path
GET https://localhost:9443/static/file.css
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Static handler"


# handle uses default when nothing matches
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Default handler"


# Configure Caddy with handle and named matchers
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
	@api {
		path /api/*
		method GET
	}
	handle @api {
		respond "GET API"
	}
	handle /api/* {
		respond "Other API methods"
	}
	handle {
		respond "Not API"
	}
}
```

# handle evaluates named matchers correctly
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "GET API"


# handle falls through to next handler when matcher doesn't match
POST https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other API methods"


# handle uses final fallback
GET https://localhost:9443/home
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


# Configure Caddy with handle and mutually exclusive paths
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
	handle /foo {
		respond "foo"
	}
	handle /foo/bar {
		respond "foo/bar"
	}
	handle {
		respond "neither"
	}
}
```

# handle stops at first match (doesn't cascade)
GET https://localhost:9443/foo
[Options]
insecure: true
HTTP 200
[Asserts]
body == "foo"


# Configure Caddy with handle containing multiple directives
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
	handle /api/* {
		header X-Handler "API"
		uri strip_prefix /api
		respond "Path: {uri}"
	}
	handle {
		respond "Not handled"
	}
}
```

# handle can contain multiple directives
GET https://localhost:9443/api/test
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Handler" == "API"
body == "Path: /test"


# Configure Caddy with handle_path
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
	handle_path /api/* {
		respond "Path after strip: {uri}"
	}
	handle {
		respond "Original: {uri}"
	}
}
```

# handle_path automatically strips prefix
GET https://localhost:9443/api/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Path after strip: /v1/users"


# handle_path doesn't affect non-matching paths
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Original: /other"
