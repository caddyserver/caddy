# Configure Caddy with intercept copying headers
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
	intercept {
		@all status 2xx
		handle_response @all {
			header X-Intercepted "yes"
		}
	}
	respond "Original"
}
```

# intercept can add headers while passing the original body through
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Intercepted" == "yes"
body == "Original"


# Configure Caddy with intercept replacing content
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
	intercept {
		@all status 2xx
		handle_response @all {
			respond "Intercepted response"
		}
	}
	respond "Original"
}
```

# intercept can completely replace response
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Intercepted response"


# Configure Caddy with replace_status using an inline status code
# NOTE: the next two scenarios document the intended behavior of replace_status
# and currently fail due to an upstream bug in intercept's WriteHeader receiver.
# Fixed in #7810
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
	intercept {
		replace_status 404
	}
	respond "Original" 200
}
```

# replace_status overrides the upstream status code while passing the body through
GET https://localhost:9443/
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Original"


# Configure Caddy with replace_status using a named response matcher
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
	intercept {
		@server_error status 5xx
		replace_status @server_error 503
	}
	route /boom {
		respond "kaboom" 500
	}
	respond "ok" 200
}
```

# replace_status rewrites the status only when the matcher matches
GET https://localhost:9443/boom
[Options]
insecure: true
HTTP 503
[Asserts]
body == "kaboom"


# unmatched responses are passed through unchanged
GET https://localhost:9443/healthy
[Options]
insecure: true
HTTP 200
[Asserts]
body == "ok"
