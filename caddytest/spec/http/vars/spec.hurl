# Configure Caddy with vars directive
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
	vars my_var "custom_value"
	vars another_var "another_value"
	respond "{vars.my_var} {vars.another_var}"
}
```

# Variables are accessible in placeholders
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "custom_value another_value"


# Configure Caddy with vars using placeholders
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
	vars request_path {path}
	vars request_method {method}
	respond "Path: {vars.request_path}, Method: {vars.request_method}"
}
```

# Variables can be set from request placeholders
GET https://localhost:9443/test/path
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Path: /test/path, Method: GET"


# POST method is captured correctly
POST https://localhost:9443/another
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Path: /another, Method: POST"


# Configure Caddy with vars in route
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
		vars api_version "v1"
		respond "API {vars.api_version}"
	}
	respond "Not API"
}
```

# Variables are scoped to their route
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API v1"


# Outside the route, variables are not set
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


# Configure Caddy with vars overwriting
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
	# without `route`, middlewares are sorted an unstable sort
	route {
		vars my_var "2"
		vars my_var "1"
	}
	respond "{vars.my_var}"
}
```

# Later vars directives overwrite earlier ones
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "1"
