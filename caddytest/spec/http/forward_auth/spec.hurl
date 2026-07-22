# Configure Caddy with forward_auth directive
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
	forward_auth localhost:9080 {
		uri /auth
	}
	respond "Protected content"
}
http://localhost:9080 {
	handle /auth {
		respond 200
	}
}
```

# forward_auth allows request when auth endpoint returns 2xx
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "Protected content"


# Configure Caddy with forward_auth rejecting
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
	forward_auth localhost:9080 {
		uri /auth
	}
	respond "Protected content"
}
http://localhost:9080 {
	handle /auth {
		respond 401
	}
}
```

# forward_auth blocks request when auth endpoint returns 4xx
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 401


# Configure Caddy with forward_auth copying headers
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
	forward_auth localhost:9080 {
		uri /auth
		copy_headers X-User-ID X-User-Email
	}
	respond "User: {header.X-User-ID}, Email: {header.X-User-Email}"
}
http://localhost:9080 {
	handle /auth {
		header X-User-ID "user123"
		header X-User-Email "user@example.com"
		respond 200
	}
}
```

# forward_auth copies specified headers from auth response
GET https://localhost:9443
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "User: user123, Email: user@example.com"


# Configure Caddy with forward_auth and custom headers
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
	forward_auth localhost:9080 {
		uri /auth
		header_up X-Original-URL {uri}
	}
	respond "OK"
}
http://localhost:9080 {
	handle /auth {
		respond "{header.X-Original-URL}"
	}
}
```

# forward_auth can send custom headers to auth endpoint
GET https://localhost:9443/test/path
[Options]
delay: 500ms
insecure: true
HTTP 200
[Asserts]
body == "OK"
