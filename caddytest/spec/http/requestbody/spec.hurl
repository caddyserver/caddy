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
        max_size 3B
    }
    reverse_proxy localhost:8000 # to fake body reading
	handle_errors 4xx {
		respond "Too large"
	}
}
http://localhost:8000 {
	respond "{http.request.body}"
}
```

# request_body accepts a body exactly at the configured size limit
POST https://localhost:9443
[Options]
delay: 1s
insecure: true
```
ok
```
HTTP 200
[Asserts]
body == "ok\n"

# request_body rejects a body larger than the configured size limit
POST https://localhost:9443
[Options]
delay: 1s
insecure: true
```
Hello
```
HTTP 413
`Too large`

# TODO: how to test{read,write}_timeout?