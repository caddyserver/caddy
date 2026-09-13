# Configure Caddy with uri strip_prefix
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
	uri strip_prefix /api
	respond {uri}
}
```

# strip_prefix removes the prefix from the URI
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/users"


# URI without prefix is unchanged
GET https://localhost:9443/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/users"


# Configure Caddy with uri strip_suffix
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
	uri strip_suffix .php
	respond {uri}
}
```

# strip_suffix removes the suffix from the URI
GET https://localhost:9443/index.php
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/index"


# URI without suffix is unchanged
GET https://localhost:9443/index.html
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/index.html"


# Configure Caddy with uri replace
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
	uri replace old new
	respond {uri}
}
```

# replace substitutes all occurrences
GET https://localhost:9443/old/path/old
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/new/path/new"


# Configure Caddy with uri path_regexp
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
	uri path_regexp /([0-9]+) /$1/id
	respond {uri}
}
```

# path_regexp replaces using regular expressions
GET https://localhost:9443/123
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/123/id"


# Configure Caddy with uri query operations
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
	uri query +foo bar
	respond {query}
}
```

# query operations add parameters
GET https://localhost:9443/?existing=value
[Options]
insecure: true
HTTP 200
[Asserts]
body == "existing=value&foo=bar"


# Configure Caddy with uri query delete
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
	uri query -sensitive
	respond {query}
}
```

# query operations delete parameters
GET https://localhost:9443/?keep=this&sensitive=secret
[Options]
insecure: true
HTTP 200
[Asserts]
body == "keep=this"


# Configure Caddy with uri query rename
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
	uri query old>new
	respond {query}
}
```

# query operations rename parameters
GET https://localhost:9443/?old=value
[Options]
insecure: true
HTTP 200
[Asserts]
body == "new=value"
