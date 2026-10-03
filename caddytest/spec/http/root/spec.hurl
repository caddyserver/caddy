# Configure Caddy with root directive
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
	root * {{indexed_root}}
	file_server
}
```

# Root directive sets the file root for file_server
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# Configure Caddy with conditional root
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
	root /api/* {{indexed_root}}
	root * {{unindexed_root}}
	respond {http.vars.root}
}
```

# Root is set conditionally based on path matcher
GET https://localhost:9443/api/test
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "indexed"


# Different root for non-matching paths
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "unindexed"


# Configure Caddy with root using placeholders
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
	vars folder "indexed"
	root * caddytest/spec/http/file_server/assets/{vars.folder}
	file_server
}
```

# Root can use placeholders
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"
