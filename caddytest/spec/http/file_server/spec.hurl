# Configure Caddy with default configuration
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
	root {{indexed_root}}
	file_server
}
```

# requests without specific file receive index file per
# the default index list: index.html, index.txt
GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
```
<!DOCTYPE html>
<html>
	<head>
		<title>Index.html Title</title>
	</head>
	<body>
		Index.html
	</body>
</html>```


# if index.txt is specifically requested, we expect index.txt
GET https://localhost:9443/index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"

# requests for sub-folder followed by .. result in sanitized path
GET https://localhost:9443/non-existent/../index.txt
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"

# results out of root folder are sanitized,
# and conform to default index list sequence.
GET https://localhost:9443/../
[Options]
insecure: true
HTTP 200
[Asserts]
```
<!DOCTYPE html>
<html>
	<head>
		<title>Index.html Title</title>
	</head>
	<body>
		Index.html
	</body>
</html>```


# Configure Caddy with custsom index "index.txt"
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
	root {{indexed_root}}
	file_server {
		index index.txt
	}
}
```

GET https://localhost:9443
[Options]
insecure: true
HTTP 200
[Asserts]
body == "index.txt"


# Configure with a root not containing index files
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
	root {{unindexed_root}}
	file_server
}
```

GET https://localhost:9443
[Options]
insecure: true
HTTP 404