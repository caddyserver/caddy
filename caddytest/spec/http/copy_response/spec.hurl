# Spec: copy_response / copy_response_headers — only valid inside
# reverse_proxy { handle_response { ... } } blocks. Every config below
# includes an inline backend on :9081 because POST /load fully replaces
# the previous configuration (no shared state across cases).

# Configure reverse_proxy with copy_response that always copies the backend response
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	respond /api "Backend Response" 200
	respond /notfound "Not Found" 404
	header /with-headers {
		X-Backend-Header "backend-value"
		X-Custom "custom"
	}
	respond /with-headers "Has Headers" 200
}

localhost {
	reverse_proxy localhost:9081 {
		handle_response {
			copy_response
		}
	}
}
```
HTTP 200

# copy_response copies a successful backend response
GET https://localhost:9443/api
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Backend Response"

# copy_response copies error responses too
GET https://localhost:9443/notfound
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Not Found"


# Configure copy_response that forces a status code on the copied body
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	respond /api "Backend Response" 200
	respond /notfound "Not Found" 404
}

localhost {
	reverse_proxy localhost:9081 {
		@notfound status 404
		handle_response @notfound {
			copy_response 502
		}
		handle_response {
			respond "Handled 404" 200
		}
	}
}
```
HTTP 200

# copy_response with an explicit status overrides the backend status while copying the body
GET https://localhost:9443/notfound
[Options]
insecure: true
HTTP 502
[Asserts]
body == "Not Found"

# unmatched (2xx) responses fall through to the second handle_response
GET https://localhost:9443/api
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Handled 404"


# Configure copy_response_headers with an include list
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	header /with-headers {
		X-Backend-Header "backend-value"
		X-Custom "custom"
	}
	respond /with-headers "Has Headers" 200
}

localhost {
	reverse_proxy localhost:9081 {
		handle_response {
			copy_response_headers {
				include X-Backend-Header
			}
			respond "Custom Body" 200
		}
	}
}
```
HTTP 200

# copy_response_headers with include copies only the listed header
# (HTTP/1.1 to avoid Content-Length / body-size H2 strict-framing conflict)
GET https://localhost:9443/with-headers
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Backend-Header" == "backend-value"
body == "Custom Body"


# Configure copy_response_headers with an exclude list
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	header /with-headers {
		X-Backend-Header "backend-value"
		X-Custom "custom"
	}
	respond /with-headers "Has Headers" 200
}

localhost {
	reverse_proxy localhost:9081 {
		handle_response {
			copy_response_headers {
				exclude X-Custom Content-Length
			}
			respond "Modified Response" 200
		}
	}
}
```
HTTP 200

# copy_response_headers with exclude drops X-Custom but keeps X-Backend-Header
GET https://localhost:9443/with-headers
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Backend-Header" == "backend-value"
body == "Modified Response"


# Configure copy_response gated by a named matcher inside handle_response
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	respond /api "Backend Response" 200
	respond /notfound "Not Found" 404
}

localhost {
	reverse_proxy localhost:9081 {
		@404 status 404
		handle_response @404 {
			copy_response
		}
		handle_response {
			respond "Default Response" 200
		}
	}
}
```
HTTP 200

# named matcher triggers copy_response on 404
GET https://localhost:9443/notfound
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Not Found"

# named matcher does not trigger on 200, so the default handle_response runs
GET https://localhost:9443/api
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Default Response"


# Configure multiple handle_response blocks dispatched by status range
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	respond /api "Backend Response" 200
	respond /notfound "Not Found" 404
}

localhost {
	reverse_proxy localhost:9081 {
		@error status 4xx 5xx
		@success status 2xx
		handle_response @error {
			copy_response
		}
		handle_response @success {
			copy_response_headers {
				exclude Content-Length
			}
			respond "Success: {http.reverse_proxy.status_code}" 200
		}
	}
}
```
HTTP 200

# 4xx route copies the backend's body
GET https://localhost:9443/notfound
[Options]
insecure: true
HTTP 404
[Asserts]
body == "Not Found"

# 2xx route swaps in a synthetic body
GET https://localhost:9443/api
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "Success:"


# Configure copy_response_headers with a wildcard include pattern
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}

:9081 {
	header /with-headers {
		X-Backend-Header "backend-value"
		X-Custom "custom"
	}
	respond /with-headers "Has Headers" 200
}

localhost {
	reverse_proxy localhost:9081 {
		handle_response {
			copy_response_headers {
				include X-Backend-Header X-Custom
			}
			respond "Headers copied" 200
		}
	}
}
```
HTTP 200

# multi-name include copies every listed header
GET https://localhost:9443/with-headers
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Backend-Header" == "backend-value"
header "X-Custom" == "custom"
body == "Headers copied"
