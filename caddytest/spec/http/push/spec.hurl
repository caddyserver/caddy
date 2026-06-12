# push initiates HTTP/2 PUSH_PROMISE frames; libcurl does not surface pushed
# streams as headers, so we only validate that push configurations parse and
# do not break the response.

# Configure Caddy with a single push target
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
	push /style.css
	file_server
}
```
HTTP 200

# push does not break the response
GET https://localhost:9443/index.html
[Options]
insecure: true
HTTP 200


# Configure Caddy with multiple push targets
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
	push /index.txt
	push /index.html
	respond "Main"
}
```
HTTP 200

# multiple push targets do not break the response
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Main"


# Configure Caddy with conditional push gated by a matcher
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
	@html path *.html
	push @html /index.txt
	file_server
}
```
HTTP 200

# matching path still serves correctly
GET https://localhost:9443/index.html
[Options]
insecure: true
HTTP 200

# non-matching path also serves correctly
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200


# Configure Caddy with push driven by upstream Link header
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
	push
	header Link "</preload.css>; rel=preload; as=style"
	respond "Linked"
}
```
HTTP 200

# bare push parses and forwards the Link header to the client
GET https://localhost:9443/
[Options]
insecure: true
HTTP 200
[Asserts]
header "Link" contains "</preload.css>"
body == "Linked"
