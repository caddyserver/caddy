# Configure Caddy with route directive
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
		uri strip_prefix /api
		respond "API: {uri}"
	}
	respond "Not API"
}
```

# route groups handlers and maintains order
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API: /users"


# route doesn't match non-matching paths
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


# Configure Caddy with nested routes
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
		uri strip_prefix /api
		route /v1/* {
			uri strip_prefix /v1
			respond "API v1: {uri}"
		}
		respond "API: {uri}"
	}
}
```

# nested routes process sequentially
GET https://localhost:9443/api/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API v1: /users"


# outer route processes when inner doesn't match
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API: /users"


# Configure Caddy with route and terminal handlers
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
	route {
		header X-First "1"
		respond "Response"
		header X-Second "2"
	}
}
```

# route stops at terminal handler (respond)
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-First" == "1"
header "X-Second" not exists


# Configure Caddy with route preserving handler order
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
	route {
		vars step1 "done"
		vars step2 "done"
		vars step3 "done"
		respond "{vars.step1},{vars.step2},{vars.step3}"
	}
}
```

# route preserves exact handler order
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "done,done,done"


# Configure Caddy with route and matchers
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
	route {
		@api path /api/*
		vars @api type "api"
		vars type "other"
		respond "{vars.type}"
	}
}
```

# route applies matchers in sequence
GET https://localhost:9443/api/test
[Options]
insecure: true
HTTP 200
[Asserts]
body == "other"


# route continues when matcher doesn't match
GET https://localhost:9443/test
[Options]
insecure: true
HTTP 200
[Asserts]
body == "other"
