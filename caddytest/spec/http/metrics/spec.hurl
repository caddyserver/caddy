# Configure Caddy with metrics endpoint
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
	servers {
		metrics
	}
}
localhost {
	handle /metrics {
		metrics
	}
	
	respond /hello "Hello, World!" 200
	respond /api "API" 200
}
```

# Metrics endpoint is accessible
GET https://localhost:9443/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"


# Metrics contain Caddy metrics
GET https://localhost:9443/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "caddy_"


# Generate some traffic to record metrics
GET https://localhost:9443/hello
[Options]
insecure: true
HTTP 200

GET https://localhost:9443/hello
[Options]
insecure: true
HTTP 200

GET https://localhost:9443/api
[Options]
insecure: true
HTTP 200


# Metrics contain HTTP metrics after requests
GET https://localhost:9443/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
body contains "caddy_http"


# Non-metrics endpoints still work normally
GET https://localhost:9443/hello
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Hello, World!"


# Configure Caddy with custom metrics path
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
	servers {
		metrics
	}
}
localhost {
	handle /custom-metrics {
		metrics
	}
	
	respond "OK" 200
}
```

# Custom metrics path works
GET https://localhost:9443/custom-metrics
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"
body contains "caddy_"


# Default path doesn't serve metrics
GET https://localhost:9443/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
body == "OK"


# Configure Caddy with disable_openmetrics option
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
	handle /metrics {
		metrics {
			disable_openmetrics
		}
	}
}
```

# Metrics work with disable_openmetrics
GET https://localhost:9443/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"


# Configure Caddy with metrics on specific route
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
	route /internal/* {
		metrics
	}
	
	respond /public "Public" 200
	respond "Default" 200
}
```

# Metrics accessible on specific route
GET https://localhost:9443/internal/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"


# Non-metrics routes unaffected
GET https://localhost:9443/public
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Public"


# Default route works
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Default"


# POST to metrics endpoint still works
POST https://localhost:9443/internal/metrics
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"
