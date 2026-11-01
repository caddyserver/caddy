# Configure Caddy with reverse_proxy to echo server
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
	reverse_proxy localhost:8080
}
http://localhost:8080 {
	respond "Backend response: {method} {uri}"
}
```

# reverse_proxy forwards requests to upstream
GET https://localhost:9443/test
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Backend response: GET /test"


# reverse_proxy preserves query parameters
GET https://localhost:9443/api?param=value
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Backend response: GET /api?param=value"


# reverse_proxy handles POST requests
POST https://localhost:9443/submit
[Options]
delay: 500ms
insecure: true
```
{"data": "test"}
```
HTTP 200
[Asserts]
body == "Backend response: POST /submit"


# Configure reverse_proxy to an upstream that echoes the request body
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
	reverse_proxy localhost:8080
}
http://localhost:8080 {
	respond "{http.request.body}"
}
```

# reverse_proxy forwards the complete request body upstream
POST https://localhost:9443/submit
[Options]
delay: 500ms
insecure: true
```
request payload
```
HTTP 200
[Asserts]
body == "request payload\n"


# Configure Caddy with reverse_proxy and header manipulation
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
	reverse_proxy localhost:8080 {
		header_up X-Custom-Header "CustomValue"
		header_down -Server
	}
}
http://localhost:8080 {
	respond "{header.X-Custom-Header}"
}
```

# reverse_proxy adds upstream headers
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "CustomValue"


# Configure Caddy with reverse_proxy path rewriting
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
		reverse_proxy localhost:8080
	}
}
http://localhost:8080 {
	respond "Backend: {uri}"
}
```

# reverse_proxy with handle_path strips prefix
GET https://localhost:9443/api/v1/users
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Backend: /v1/users"


# Configure Caddy with reverse_proxy to multiple upstreams
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
	reverse_proxy localhost:8080 localhost:8081 {
		lb_policy round_robin
	}
}
http://localhost:8080 {
	respond "Backend 1"
}
http://localhost:8081 {
	respond "Backend 2"
}
```

# reverse_proxy load balances between upstreams
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Backend 1"


# round_robin sends the next request to the other upstream
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Backend 2"


# Configure Caddy with reverse_proxy and transport options
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
	reverse_proxy localhost:8080 {
		transport http {
			dial_timeout 2s
		}
	}
}
http://localhost:8080 {
	respond "OK"
}
```

# reverse_proxy respects transport settings
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "OK"


# Configure Caddy with reverse_proxy and flush_interval
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
	reverse_proxy localhost:8080 {
		flush_interval -1
	}
}
http://localhost:8080 {
	respond "Streaming response"
}
```

# reverse_proxy handles streaming with flush_interval
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Streaming response"
