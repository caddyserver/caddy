# Configure Caddy with templates directive
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
	templates
	respond "Request path: \{\{.OriginalReq.URL.Path}}"
}
```

# templates processes template syntax
GET https://localhost:9443/test/path
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Request path: /test/path"


# Configure Caddy with templates and file_server
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
	templates
	file_server
}
```

# templates doesn't process non-template files
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# Configure Caddy with templates and placeholders
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
	templates
	respond "Method: \{\{.Req.Method}}, Host: \{\{.Req.Host}}"
}
```

# templates exposes request properties
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Method: GET, Host: localhost:9443"


# POST method is accessible in templates
POST https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Method: POST, Host: localhost:9443"


# Configure Caddy with templates and functions
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
	templates
	respond "\{\{upper \"hello world\"}}"
}
```

# templates provides utility functions
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "HELLO WORLD"


# Configure Caddy with templates conditionals
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
	templates
	respond "\{\{if eq .Req.Method \"GET\"}}GET method\{\{else}}Other method\{\{end}}"
}
```

# templates supports conditionals
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "GET method"


# templates conditional for other methods
POST https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other method"


# Configure Caddy with templates and environment variables
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
	templates
	respond "Path: \{\{env \"PATH\"}}"
}
```

# templates can access environment variables
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "Path:"
body contains "/"
