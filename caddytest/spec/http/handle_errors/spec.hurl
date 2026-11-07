# Configure Caddy with handle_errors directive
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
	root * /nonexistent
	file_server
	handle_errors {
		respond "Error {err.status_code}: {err.status_text}"
	}
}
```

# handle_errors catches file_server 404 errors
GET https://localhost:9443/missing.txt
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Error 404: Not Found"


# Configure Caddy with handle_errors for specific status codes
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
	error /forbidden* "Forbidden" 403
	error /gone* "Gone" 410
	handle_errors 403 {
		respond "Custom 403 handler"
	}
	handle_errors 4xx {
		respond "Generic 4xx handler: {err.status_code}"
	}
}
```

# handle_errors matches specific 403 handler
GET https://localhost:9443/forbidden
[Options]
insecure: true
HTTP 403
[Asserts]
body == "Custom 403 handler"


# handle_errors uses 4xx handler for other client errors
GET https://localhost:9443/gone
[Options]
insecure: true
HTTP 410
[Asserts]
body == "Generic 4xx handler: 410"


# Configure Caddy with handle_errors using templates
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
	root * /nonexistent
	file_server
	handle_errors {
		respond "Path: {http.request.orig_uri.path}, Status: {err.status_code}"
	}
}
```

# handle_errors has access to request context
GET https://localhost:9443/test/missing.html
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Path: /test/missing.html, Status: 404"


# Configure Caddy with nested error handling
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
	error /fail 500
	handle_errors 5xx {
		respond "Server error occurred"
	}
	handle_errors 4xx {
		respond "Client error occurred"
	}
}
```

# handle_errors matches 5xx errors
GET https://localhost:9443/fail
[Options]
insecure: true
HTTP 500
[Asserts]
body == "Server error occurred"


# Configure Caddy with handle_errors and error ID
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
	error /test "Test error" 400
	handle_errors {
		respond "Error ID: {err.id}, Message: {err.message}"
	}
}
```

# handle_errors exposes error ID and message
GET https://localhost:9443/test
[Options]
insecure: true
HTTP 400
[Asserts]
body contains "Error ID:"
body contains "Message: Test error"


# Configure Caddy with handle_errors rewrite
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
	root * {{indexed_root}}
	file_server
	handle_errors 404 {
		rewrite * /index.html
		file_server
	}
}
```

# handle_errors can rewrite and serve different file
GET https://localhost:9443/nonexistent.txt
[Options]
insecure: true
HTTP 404
[Asserts]
body contains "Index.html"


# Configure Caddy with multiple status codes on a single handle_errors block
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
	error /a "A" 403
	error /b "B" 404
	error /c "C" 500
	handle_errors 403 404 {
		respond "auth-or-missing: {err.status_code}"
	}
	handle_errors {
		respond "other: {err.status_code}"
	}
}
```

# multiple codes on one handle_errors block — first code
GET https://localhost:9443/a
[Options]
insecure: true
HTTP 403
[Asserts]
body == "auth-or-missing: 403"

# multiple codes on one handle_errors block — second code
GET https://localhost:9443/b
[Options]
insecure: true
HTTP 404
[Asserts]
body == "auth-or-missing: 404"

# catch-all handle_errors block matches unlisted codes (and stays last)
GET https://localhost:9443/c
[Options]
insecure: true
HTTP 500
[Asserts]
body == "other: 500"


# Configure Caddy with a mix of single code and range on one block
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
	error /redir   "Moved"      301
	error /server  "Internal"   500
	error /client  "Bad"        400
	handle_errors 500 3xx {
		respond "redirect-or-server: {err.status_code}"
	}
	handle_errors 4xx {
		respond "client: {err.status_code}"
	}
}
```

# mixed-range handle_errors matches the single code (500)
GET https://localhost:9443/server
[Options]
insecure: true
HTTP 500
[Asserts]
body == "redirect-or-server: 500"

# mixed-range handle_errors matches the range (3xx)
GET https://localhost:9443/redir
[Options]
insecure: true
HTTP 301
[Asserts]
body == "redirect-or-server: 301"

# unrelated range still matches its dedicated handler
GET https://localhost:9443/client
[Options]
insecure: true
HTTP 400
[Asserts]
body == "client: 400"


# Configure Caddy with two specific-code handlers in declaration order
# Regression guard: the matcher-set sort must preserve user-declared order
# when neither block is a catch-all (otherwise a status-specific block can
# end up swapped with another and the wrong body is returned).
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
	error /forbidden "Forbidden" 403
	error /missing   "Missing"   404
	handle_errors 403 {
		respond "first: 403"
	}
	handle_errors 404 {
		respond "second: 404"
	}
}
```

# 403 hits the first handler
GET https://localhost:9443/forbidden
[Options]
insecure: true
HTTP 403
[Asserts]
body == "first: 403"

# 404 hits the second handler
GET https://localhost:9443/missing
[Options]
insecure: true
HTTP 404
[Asserts]
body == "second: 404"


# Configure Caddy with specific handlers declared before a catch-all
# This pins the only intentional reordering rule: catch-all goes last.
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
	error /forbidden "Forbidden" 403
	error /teapot    "Teapot"    418
	handle_errors 403 {
		respond "specific: 403"
	}
	handle_errors {
		respond "catch-all: {err.status_code}"
	}
}
```

# specific handler still wins when declared before the catch-all
GET https://localhost:9443/forbidden
[Options]
insecure: true
HTTP 403
[Asserts]
body == "specific: 403"

# catch-all picks up codes the specific handler does not list
GET https://localhost:9443/teapot
[Options]
insecure: true
HTTP 418
[Asserts]
body == "catch-all: 418"

