# Configure Caddy with abort directive
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
	abort
	respond "This should not be reached"
}
```

# NOTE: bare `abort` aborts the request without sending a response, so the
# client sees a transport-level connection close. We cannot assert this in
# Hurl (it errors on the broken HTTP exchange). The Caddyfile above is
# accepted and provisioned successfully, which the /load probe confirms.


# Configure Caddy with conditional abort
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
	@blocked path /blocked*
	abort @blocked
	respond "OK"
}
```

# abort only affects matching paths
GET https://localhost:9443/allowed
[Options]
insecure: true
HTTP 200
[Asserts]
body == "OK"


# Configure Caddy with abort in route
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
	route /api/* {
		@invalid header X-API-Key ""
		abort @invalid
		respond "API OK"
	}
	respond "Not API"
}
```

# abort in route for matching condition
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


# Configure Caddy with abort after headers
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
	@crawler header User-Agent *bot*
	abort @crawler
	respond "Normal user"
}
```

# abort based on User-Agent header
GET https://localhost:9443
User-Agent: Mozilla/5.0
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Normal user"
