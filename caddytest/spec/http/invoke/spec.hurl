# Configure Caddy with invoke directive and a named route
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
&(api) {
	respond "API response"
}
localhost {
	invoke api
}
```
HTTP 200

# invoke runs the named route inline
GET https://localhost:9443/anything
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API response"


# Configure Caddy with invoke gated by a matcher
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
&(api) {
	respond "API: invoked"
}
localhost {
	@api path /api/*
	handle @api {
		invoke api
	}
	respond "default"
}
```
HTTP 200

# matcher selects the invoke
GET https://localhost:9443/api/foo
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API: invoked"

# non-matching path falls through to default handler
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "default"


# Configure Caddy with multiple named routes invoked from different sites
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
&(v1) {
	respond "Version: v1"
}
&(v2) {
	respond "Version: v2"
}
localhost {
	@v1 path /v1/*
	@v2 path /v2/*
	handle @v1 {
		invoke v1
	}
	handle @v2 {
		invoke v2
	}
	respond "Version: unknown"
}
```
HTTP 200

# /v1/ invokes the v1 named route
GET https://localhost:9443/v1/anything
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Version: v1"

# /v2/ invokes the v2 named route
GET https://localhost:9443/v2/anything
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Version: v2"

# unmatched path falls back
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Version: unknown"


# Configure Caddy with a non-terminal named route followed by a respond
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
&(addheader) {
	header X-Middleware "applied"
}
localhost {
	invoke addheader
	respond "Done"
}
```
HTTP 200

# invoke can run non-terminal handlers that mutate the response
GET https://localhost:9443/test
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Middleware" == "applied"
body == "Done"


# Configure Caddy with a named route used by both a route and a handle block
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
&(echo) {
	respond "echoed"
}
localhost {
	@a path /route-style
	@b path /handle-style
	route @a {
		invoke echo
	}
	handle @b {
		invoke echo
	}
	respond "default"
}
```
HTTP 200

# invoke from inside route { }
GET https://localhost:9443/route-style
[Options]
insecure: true
HTTP 200
[Asserts]
body == "echoed"

# invoke from inside handle { }
GET https://localhost:9443/handle-style
[Options]
insecure: true
HTTP 200
[Asserts]
body == "echoed"
