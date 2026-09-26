# Configure Caddy
POST http://localhost:2019/load
Content-Type: text/caddyfile
```
{
	skip_install_trust
	http_port     9080
	https_port    9443
	local_certs
	debug
}
localhost {
	log
	basic_auth {
		john $2a$14$x4HlYwA9Zeer4RkMEYbUzug9XxWmncneR.dcMs.UjalR95URnHg5.
	}
	respond "Hello, World!"
}
```

# requests without `Authorization` header are rejected with 401
GET https://localhost:9443
[Options]
insecure: true
HTTP 401
[Asserts]
header "WWW-Authenticate" == "Basic realm=\"restricted\""


# requests with `Authorization` header are accepted with 200
GET https://localhost:9443
[BasicAuth]
john:password
[Options]
insecure: true
HTTP 200
[Asserts]
`Hello, World!`
