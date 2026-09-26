# Spec: fs directive — selects which named filesystem to use for file_server etc.
# Only the "default" (OS) filesystem is available without external plugins.
# These tests verify the directive parses, is applied conditionally, and does
# not interfere with file_server resolving files from the configured root.

# Configure Caddy with explicit default filesystem
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
	fs default
	file_server
}
```
HTTP 200

# PROPERTY: `fs default` selects the OS-backed filesystem and serves files normally
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# PROPERTY: default filesystem honors index files for directory requests
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/html"
body contains "Index.html"


# Configure Caddy with `fs` applied conditionally via named matcher
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
	@indexed path /indexed/*
	fs @indexed default
	file_server
}
```
HTTP 200

# PROPERTY: matcher-scoped `fs` does not break unrelated paths
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# Configure Caddy with fs and browse listing
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
	root * {{unindexed_root}}
	fs default
	file_server browse
}
```
HTTP 200

# PROPERTY: fs default works with file_server browse (directory listing fallback)
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/html"
