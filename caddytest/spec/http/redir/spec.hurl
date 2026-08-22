# Configure Caddy with basic redirect
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
	redir /old /new
}
```

# Basic redirect from /old to /new with default 302 status
GET https://localhost:9443/old
[Options]
insecure: true
location: false
HTTP 302
[Asserts]
header "Location" == "/new"


# Non-matching paths are not redirected
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200


# Configure Caddy with permanent redirect
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
	redir /old /new permanent
}
```

# Permanent redirect uses 301 status
GET https://localhost:9443/old
[Options]
insecure: true
location: false
HTTP 301
[Asserts]
header "Location" == "/new"


# Configure Caddy with temporary redirect
# NOTE: `temporary` is documented and currently implemented as 302 (Found),
# not the semantically stricter 307 (Temporary Redirect). See
# https://github.com/caddyserver/caddy/issues/7348 for the discrepancy.
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
	redir /old /new temporary
}
```

# temporary redirect uses 302 status (same as default; see issue #7348)
GET https://localhost:9443/old
[Options]
insecure: true
location: false
HTTP 302
[Asserts]
header "Location" == "/new"


# Configure Caddy with full URL redirect
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
	redir https://example.com{uri}
}
```

# Full URL redirect preserves the URI
GET https://localhost:9443/path?query=value
[Options]
insecure: true
location: false
HTTP 302
[Asserts]
header "Location" == "https://example.com/path?query=value"


# Configure Caddy with HTML redirect
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
	redir /old /new html
}
```

# HTML redirect returns 200 with meta refresh
GET https://localhost:9443/old
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/html"
body contains "<meta http-equiv=\"refresh\""
body contains "URL='/new'"


# Configure Caddy with status code redirect
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
	redir /old /new 303
}
```

# Custom status code redirect
GET https://localhost:9443/old
[Options]
insecure: true
location: false
HTTP 303
[Asserts]
header "Location" == "/new"


# Configure Caddy with wildcard path redirect
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
	redir /old/* /new{uri}
}
```

# Wildcard path redirect preserves the rest of the URI
GET https://localhost:9443/old/some/path
[Options]
insecure: true
location: false
HTTP 302
[Asserts]
header "Location" == "/new/old/some/path"
