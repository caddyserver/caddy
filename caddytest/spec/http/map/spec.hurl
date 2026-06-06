# Configure Caddy with map directive
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
	map {path} {my_var} {
		/foo "bar"
		/baz "qux"
		default "unknown"
	}
	respond "{my_var}"
}
```

# map directive maps /foo to "bar"
GET https://localhost:9443/foo
[Options]
insecure: true
HTTP 200
[Asserts]
body == "bar"


# map directive maps /baz to "qux"
GET https://localhost:9443/baz
[Options]
insecure: true
HTTP 200
[Asserts]
body == "qux"


# map directive uses default for non-matching paths
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "unknown"


# Configure Caddy with map using wildcards
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
	map {path} {result} {
		~^/api/    "api"
		~^/static/ "static"
		~^/user/(\d+)$ "user"
		default "other"
	}
	respond "{result}"
}
```

# map with wildcard matches prefix
GET https://localhost:9443/api/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "api"


# map with wildcard matches another prefix
GET https://localhost:9443/static/css/style.css
[Options]
insecure: true
HTTP 200
[Asserts]
body == "static"


# map with regexp matches pattern
GET https://localhost:9443/user/123
[Options]
insecure: true
HTTP 200
[Asserts]
body == "user"


# map default when nothing matches
GET https://localhost:9443/unknown
[Options]
insecure: true
HTTP 200
[Asserts]
body == "other"


# Configure Caddy with map using multiple sources
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
	map "{method} {path}" {result} {
		"GET /api" "get-api"
		"POST /api" "post-api"
		default "other"
	}
	respond "{result}"
}
```

# map can use multiple placeholders in source
GET https://localhost:9443/api
[Options]
insecure: true
HTTP 200
[Asserts]
body == "get-api"


# map distinguishes different methods
POST https://localhost:9443/api
[Options]
insecure: true
HTTP 200
[Asserts]
body == "post-api"


# Configure Caddy with map capture groups
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
	map {path} {result} {
		~^/([a-z]+)/([0-9]+)$ "$1-$2"
		default "no-match"
	}
	respond "{result}"
}
```

# map can extract capture groups
GET https://localhost:9443/user/42
[Options]
insecure: true
HTTP 200
[Asserts]
body == "user-42"


# map returns default when pattern doesn't match
GET https://localhost:9443/invalid/path
[Options]
insecure: true
HTTP 200
[Asserts]
body == "no-match"
