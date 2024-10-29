# Configure Caddy
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
	log
	request_body {
        max_size 2B
    }
    reverse_proxy localhost:8000 # to fake body reading
	handle_errors 4xx {
		respond "OK"
	}
}
http://localhost:8000 {
	respond "Failed"
}
```

GET https://localhost:9443
[Options]
```
Hello
```
HTTP 413
`OK`

# TODO: how to test{read,write}_timeout?