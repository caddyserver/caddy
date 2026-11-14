# Configure Caddy with a wildcard handle_path
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
		respond "stripped={uri}"
	}
	handle {
		respond "fallback={uri}"
	}
}
```

# handle_path strips the matched prefix before running its handlers
GET https://localhost:9443/api/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "stripped=/v1/users"


# handle_path leaves the leading slash when the rest of the path is empty
GET https://localhost:9443/api/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "stripped=/"


# query strings survive the prefix strip
GET https://localhost:9443/api/search?q=hello&page=2
[Options]
insecure: true
HTTP 200
[Asserts]
body == "stripped=/search?q=hello&page=2"


# non-matching paths fall through to the next handler unchanged
GET https://localhost:9443/other/thing
[Options]
insecure: true
HTTP 200
[Asserts]
body == "fallback=/other/thing"


# Configure Caddy with an exact-match handle_path (no wildcard)
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
	handle_path /healthz {
		respond "ok path={uri}"
	}
	handle {
		respond "fallback={uri}"
	}
}
```

# exact match strips the full prefix; Caddy normalizes the URI back to "/"
GET https://localhost:9443/healthz
[Options]
insecure: true
HTTP 200
[Asserts]
body == "ok path=/"


# exact-match handle_path does not match deeper paths
GET https://localhost:9443/healthz/extra
[Options]
insecure: true
HTTP 200
[Asserts]
body == "fallback=/healthz/extra"


# Configure Caddy with multiple directives inside a handle_path block
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
	handle_path /admin/* {
		header X-Section "admin"
		respond "admin uri={uri}"
	}
	handle {
		respond "public uri={uri}"
	}
}
```

# directives inside the block run against the stripped path
GET https://localhost:9443/admin/users/list
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Section" == "admin"
body == "admin uri=/users/list"


# Configure Caddy with two handle_path blocks ordered by specificity
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
	handle_path /api/v2/* {
		respond "v2={uri}"
	}
	handle_path /api/* {
		respond "v1={uri}"
	}
	handle {
		respond "none={uri}"
	}
}
```

# the more-specific handle_path wins for matching paths
GET https://localhost:9443/api/v2/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "v2=/users"


# the broader handle_path catches everything else under the prefix
GET https://localhost:9443/api/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "v1=/v1/users"


# Configure Caddy with handle_path inside an explicit route
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
	header X-Site "demo"
	handle_path /strip/* {
		respond "after={uri}"
	}
}
```

# server-level directives still apply when handle_path matches
GET https://localhost:9443/strip/deep/path
[Options]
insecure: true
HTTP 200
[Asserts]
header "X-Site" == "demo"
body == "after=/deep/path"
