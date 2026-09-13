# Configure Caddy with encode directive
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
	encode gzip {
		minimum_length 1
	}
	respond "This is a test response that should not be compressed with gzip encoding."
}
```

# encode gzip compresses responses when client accepts gzip
GET https://localhost:9443
Accept-Encoding: gzip
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" == "gzip"
header "Vary" contains "Accept-Encoding"


# encode does not compress when client doesn't accept encoding
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" not exists


# Configure Caddy with multiple encoding formats
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
	encode zstd gzip {
		minimum_length 1
	}
	respond "This is a test response that should be compressed."
}
```

# encode prefers zstd when client accepts it
GET https://localhost:9443
Accept-Encoding: gzip, zstd
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" == "zstd"


# encode falls back to gzip when zstd not accepted
GET https://localhost:9443
Accept-Encoding: gzip
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" == "gzip"


# Configure Caddy with encode matching
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
	encode gzip {
		match {
			header Content-Type text/*
		}
		minimum_length 1
	}
	header Content-Type text/plain
	respond {path} {
		close
	}
}
```

# encode only compresses matching content types
GET https://localhost:9443/test.txt
Accept-Encoding: gzip
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" == "gzip"


# Configure Caddy with encode minimum length
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
	encode gzip {
		minimum_length 100
	}
	respond "short"
}
```

# encode respects minimum length (should not compress)
GET https://localhost:9443
Accept-Encoding: gzip
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" not exists
body == "short"


# Configure Caddy with large response
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
	encode gzip {
		minimum_length 10
	}
	respond "This is a longer response that should definitely be compressed because it exceeds the minimum length."
}
```

# encode compresses when exceeding minimum length
GET https://localhost:9443
Accept-Encoding: gzip
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" == "gzip"


# Configure Caddy with brotli encoding
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
	encode zstd gzip {
		minimum_length 1
	}
	respond "This response can be compressed with zstd or gzip."
}
```

# encode picks the first listed encoder when the client accepts it
GET https://localhost:9443
Accept-Encoding: gzip, zstd
[Options]
insecure: true
HTTP 200
[Asserts]
header "Content-Encoding" == "zstd"
