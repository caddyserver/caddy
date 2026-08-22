# Configure Caddy
POST http://localhost:2019/load
User-Agent: hurl/ci
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	rewrite /from /to
	respond {uri}
}
```

# simple scenario: rewriting /from to /to produces expected result of seeing /to
GET https://localhost:9443/from
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/to"

# unmatched path is passed through unchanged
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/"

# having a query parameter does not trip the rewrite and retains the query
GET https://localhost:9443/from?query_param=value
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/to?query_param=value"


# Configure Caddy
POST http://localhost:2019/load
User-Agent: hurl/ci
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
localhost {
	rewrite /from /to?a=b
	respond {uri}
}
```

# a rewrite with query parameters affects the parameters
GET https://localhost:9443/from?query_param=value
[Options]
insecure: true
HTTP 200
[Asserts]
body == "/to?a=b"
