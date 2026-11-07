# Configure Caddy with expression matcher for user agent
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
	@mobile expression {http.request.header.User-Agent}.contains("Mobile")
	respond @mobile "Mobile Site" 200
	
	respond "Desktop Site" 200
}
```

# Expression matcher matches mobile user agent
GET https://localhost:9443/
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) Mobile
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Mobile Site"


# Expression matcher doesn't match desktop user agent
GET https://localhost:9443/
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Desktop Site"


# Expression matcher with no user agent
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Desktop Site"


# Configure Caddy with expression for path checking
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
	@api expression {http.request.uri.path}.startsWith("/api/")
	respond @api "API Response" 200
	
	respond "Not API" 200
}
```

# Expression matches API path
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API Response"


# Expression doesn't match non-API path
GET https://localhost:9443/web/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not API"


# Configure Caddy with expression using boolean AND logic
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
	@secured expression {http.request.uri.path}.startsWith("/admin") && {http.request.method} == "POST"
	respond @secured "Admin POST" 200
	
	respond "Other Request" 200
}
```

# Expression matches both conditions (AND)
POST https://localhost:9443/admin/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Admin POST"


# Expression fails on wrong method
GET https://localhost:9443/admin/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other Request"


# Expression fails on wrong path
POST https://localhost:9443/public/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Other Request"


# Configure Caddy with expression using OR logic
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
	@static expression {http.request.uri.path}.endsWith(".jpg") || {http.request.uri.path}.endsWith(".png")
	respond @static "Image File" 200
	
	respond "Not Image" 200
}
```

# Expression matches first condition (OR)
GET https://localhost:9443/photo.jpg
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Image File"


# Expression matches second condition (OR)
GET https://localhost:9443/logo.png
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Image File"


# Expression matches neither condition
GET https://localhost:9443/document.pdf
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Not Image"


# Configure Caddy with expression for header comparison
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
	@json expression {http.request.header.Content-Type} == "application/json"
	respond @json "JSON Handler" 200
	
	respond "Other Handler" 200
}
```

# Expression matches exact header value
POST https://localhost:9443/
Content-Type: application/json
[Options]
insecure: true
```json
{"test": "data"}
```
HTTP 200
[Asserts]
body == "JSON Handler"


# Expression doesn't match different content type
POST https://localhost:9443/
Content-Type: text/plain
[Options]
insecure: true
```
test data
```
HTTP 200
[Asserts]
body == "Other Handler"


# Configure Caddy with expression for query parameter check
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
	@debug expression {http.request.uri.query}.contains("debug=true")
	respond @debug "Debug Mode" 200
	
	respond "Normal Mode" 200
}
```

# Expression matches query parameter
GET https://localhost:9443/?debug=true
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Debug Mode"


# Expression with other query parameters
GET https://localhost:9443/?user=admin&debug=true&page=1
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Debug Mode"


# Expression doesn't match without debug param
GET https://localhost:9443/?user=admin
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Normal Mode"


# Configure Caddy with expression for method checking
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
	@readonly expression {http.request.method} in ["GET", "HEAD", "OPTIONS"]
	respond @readonly "Read-only" 200
	
	respond "Write Operation" 200
}
```

# Expression matches GET method
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Read-only"


# Expression matches HEAD method
HEAD https://localhost:9443/
[Options]
insecure: true
HTTP 200


# Expression matches OPTIONS method
OPTIONS https://localhost:9443/
[Options]
insecure: true
HTTP 200


# Expression doesn't match POST method
POST https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Write Operation"


# Expression doesn't match DELETE method
DELETE https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Write Operation"


# Configure Caddy with expression using NOT operator
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
	@notadmin expression !{http.request.uri.path}.startsWith("/admin")
	respond @notadmin "Public Area" 200
	
	respond "Admin Area" 200
}
```

# Expression with NOT matches non-admin path
GET https://localhost:9443/public/page
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Public Area"


# Expression with NOT doesn't match admin path
GET https://localhost:9443/admin/panel
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Admin Area"


# Configure Caddy with expression for host checking
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
}
*.localhost {
	@api expression {http.request.host}.startsWith("api.")
	respond @api "API Host" 200
	
	respond "Web Host" 200
}
```

# Expression matches API subdomain
GET https://api.localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "API Host"


# Expression doesn't match www subdomain
GET https://www.localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Web Host"


# Configure Caddy with complex nested expression
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
	@complex expression ({http.request.method} == "POST" && {http.request.uri.path}.startsWith("/api")) || {http.request.header.X-Force} == "true"
	respond @complex "Complex Match" 200
	
	respond "No Match" 200
}
```

# Complex expression matches POST to API
POST https://localhost:9443/api/data
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Complex Match"


# Complex expression doesn't match GET to API
GET https://localhost:9443/api/data
[Options]
insecure: true
HTTP 200
[Asserts]
body == "No Match"


# Complex expression matches via force header
GET https://localhost:9443/other
X-Force: true
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Complex Match"


# Complex expression doesn't match without conditions
GET https://localhost:9443/other
[Options]
insecure: true
HTTP 200
[Asserts]
body == "No Match"


# Configure Caddy with expression for regex matching
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
	@versioned expression {http.request.uri.path}.matches("^/v[0-9]+/.*")
	respond @versioned "Versioned API" 200
	
	respond "Unversioned" 200
}
```

# Expression matches versioned path v1
GET https://localhost:9443/v1/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Versioned API"


# Expression matches versioned path v2
GET https://localhost:9443/v2/products
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Versioned API"


# Expression doesn't match unversioned path
GET https://localhost:9443/api/users
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Unversioned"
