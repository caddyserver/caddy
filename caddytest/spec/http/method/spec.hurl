# Spec: method directive — rewrites the request method. It is NOT a matcher.
# Routing by HTTP method is done with the `method` matcher (`@get method GET`).
# These tests cover both behaviours so the difference is unambiguous.

# Configure Caddy with method matcher (@m method <verb>) routing requests
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
	@get method GET
	@post method POST PUT
	handle @get {
		respond "GET method" 200
	}
	handle @post {
		respond "POST or PUT method" 200
	}
	respond "Other method" 200
}
```
HTTP 200

# PROPERTY: @method matcher routes GET to the GET handler
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "GET method"

# PROPERTY: @method matcher routes POST to the POST/PUT handler
POST https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "POST or PUT method"

# PROPERTY: @method matcher routes PUT to the same POST/PUT handler
PUT https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "POST or PUT method"

# PROPERTY: unmatched methods fall through to the catch-all handler
DELETE https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other method"

PATCH https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other method"

OPTIONS https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other method"

# PROPERTY: HEAD against a GET-matched handler returns 200 (Go strips body)
HEAD https://localhost:9443
[Options]
insecure: true
HTTP 200


# Configure Caddy with method REWRITE: changes the request method before downstream handlers
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
	# rewrite every incoming request's method to GET
	method GET
	@get method GET
	handle @get {
		respond "rewritten to GET" 200
	}
	respond "should not reach"
}
```
HTTP 200

# PROPERTY: `method GET` rewrites the request method so any verb becomes GET
POST https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "rewritten to GET"

DELETE https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "rewritten to GET"


# Configure Caddy with conditional method rewrite via path matcher
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
	method @api POST
	respond "method={method}" 200
}
```
HTTP 200

# PROPERTY: matcher-scoped method rewrite only applies to matching paths
GET https://localhost:9443/api/foo
[Options]
insecure: true
HTTP 200
[Asserts]
body == "method=POST"

# PROPERTY: non-matching paths preserve the original method
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "method=GET"
