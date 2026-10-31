# Configure Caddy with try_files directive
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
	try_files {path} {path}.txt {path}/index.html
	file_server
}
```

# try_files tries the original path first
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# try_files falls through to next option if first doesn't exist
GET https://localhost:9443/index
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# try_files falls through to directory index when the directory exists
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "Index.html"


# Configure Caddy with try_files and final fallback
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
	try_files {path} /index.html
	file_server
}
```

# try_files uses final fallback when nothing matches
GET https://localhost:9443/does-not-exist
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "Index.html"


# Configure Caddy with try_files policy
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
	try_files {path} {path}/ =404
}
```

# try_files with =404 returns 404 when no files match
GET https://localhost:9443/nonexistent
[Options]
insecure: true
HTTP 404


# Configure Caddy with try_files and query parameters
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
	try_files {path} /index.html
	file_server
}
```

# try_files preserves query parameters
GET https://localhost:9443/missing?param=value
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "Index.html"
