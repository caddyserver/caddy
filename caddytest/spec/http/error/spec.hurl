# Configure Caddy with error directive
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
	error /forbidden* "Access denied" 403
	respond "OK"
}
```

# error directive triggers 403 for matching paths
GET https://localhost:9443/forbidden/resource
[Options]
insecure: true
HTTP 403


# error directive does not trigger for non-matching paths
GET https://localhost:9443/allowed
[Options]
insecure: true
HTTP 200
[Asserts]
body == "OK"


# Configure Caddy with error and handle_errors
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
	error /admin* "Forbidden" 403
	handle_errors {
		respond "Custom error: {err.status_code} - {err.status_text}"
	}
}
```

# error with handle_errors shows custom error page
GET https://localhost:9443/admin/panel
[Options]
insecure: true
HTTP 403
[Asserts]
body == "Custom error: 403 - Forbidden"


# Configure Caddy with conditional error
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
	@admin path /admin*
	error @admin 404
	respond "Public content"
}
```

# error with named matcher triggers on match
GET https://localhost:9443/admin/users
[Options]
insecure: true
HTTP 404


# error with named matcher doesn't trigger on non-match
GET https://localhost:9443/public
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Public content"


# Configure Caddy with error for specific methods
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
	@post method POST
	error @post "Method not allowed" 405
	respond "GET OK"
}
```

# error blocks POST requests
POST https://localhost:9443
[Options]
insecure: true
HTTP 405


# error allows GET requests
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "GET OK"


# Configure Caddy with dynamic error message
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
	error /error* "Path {path} not found" 404
	handle_errors {
		respond "{err.message}"
	}
}
```

# error message can use placeholders
GET https://localhost:9443/error/test
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Path /error/test not found"
