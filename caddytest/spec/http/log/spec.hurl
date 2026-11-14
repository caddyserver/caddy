# Each block routes Caddy's access log to a unique file under
# /tmp/caddy-log-spec/ and exposes that directory via a sidecar
# `file_server` site on :9081, so a subsequent GET can read the log
# back and assert the directive actually did what it claims.
#
# `roll_disabled` keeps the writer as a plain os.File so writes are
# visible to the next read without lumberjack rotation games.
#
# Files persist between runs; if you change a config block locally you
# may want to `rm -rf /tmp/caddy-log-spec` before re-running. CI runners
# start with a clean /tmp.

# Configure Caddy with the log directive writing to a real file
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
	log {
		output file /tmp/caddy-log-spec/basic.log {
			roll_disabled
		}
		format json
	}
	respond "Logged response"
}
:9081 {
	root * /tmp/caddy-log-spec
	file_server
}
```

# Generate a logged request
GET https://localhost:9443/from-basic
[Options]
insecure: true
HTTP 200
[Asserts]
body == "Logged response"

# The log file exists and contains a JSON entry for the request above
GET http://localhost:9081/basic.log
HTTP 200
[Asserts]
body contains "\"uri\":\"/from-basic\""
body contains "\"status\":200"


# Configure Caddy with log_skip
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
	log {
		output file /tmp/caddy-log-spec/skip.log {
			roll_disabled
		}
		format json
	}
	log_skip /health
	respond "OK"
}
:9081 {
	root * /tmp/caddy-log-spec
	file_server
}
```

# Requests we want logged and requests we want skipped
GET https://localhost:9443/skip-api
[Options]
insecure: true
HTTP 200

GET https://localhost:9443/health
[Options]
insecure: true
HTTP 200

# Logged path appears, skipped path does not
GET http://localhost:9081/skip.log
HTTP 200
[Asserts]
body contains "\"uri\":\"/skip-api\""
body not contains "\"uri\":\"/health\""


# Configure Caddy with log_append
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
	log {
		output file /tmp/caddy-log-spec/append.log {
			roll_disabled
		}
		format json
	}
	log_append user_id {http.request.header.X-User-Id}
	log_append request_type "api"
	respond "OK"
}
:9081 {
	root * /tmp/caddy-log-spec
	file_server
}
```

# Request that should produce a log entry with the appended fields
GET https://localhost:9443/append-target
X-User-Id: user123
[Options]
insecure: true
HTTP 200

# Both appended fields are present in the JSON log entry
GET http://localhost:9081/append.log
HTTP 200
[Asserts]
body contains "\"uri\":\"/append-target\""
body contains "\"user_id\":\"user123\""
body contains "\"request_type\":\"api\""


# Configure Caddy with log_name routing requests to different loggers
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
	log api_log {
		output file /tmp/caddy-log-spec/name_api.log {
			roll_disabled
		}
		format json
	}
	log static_log {
		output file /tmp/caddy-log-spec/name_static.log {
			roll_disabled
		}
		format json
	}
	log_name /api/* api_log
	log_name /static/* static_log
	respond "OK"
}
:9081 {
	root * /tmp/caddy-log-spec
	file_server
}
```

# Drive requests into each logger
GET https://localhost:9443/api/probe
[Options]
insecure: true
HTTP 200

GET https://localhost:9443/static/style.css
[Options]
insecure: true
HTTP 200

# api_log only contains /api entries
GET http://localhost:9081/name_api.log
HTTP 200
[Asserts]
body contains "\"uri\":\"/api/probe\""
body not contains "\"uri\":\"/static/style.css\""

# static_log only contains /static entries
GET http://localhost:9081/name_static.log
HTTP 200
[Asserts]
body contains "\"uri\":\"/static/style.css\""
body not contains "\"uri\":\"/api/probe\""


# Configure Caddy with log_skip driven by a named matcher
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
	log {
		output file /tmp/caddy-log-spec/named_matcher.log {
			roll_disabled
		}
		format json
	}
	@health path /healthz /ready
	log_skip @health
	respond "OK"
}
:9081 {
	root * /tmp/caddy-log-spec
	file_server
}
```

# One logged path and two skipped paths
GET https://localhost:9443/named-api
[Options]
insecure: true
HTTP 200

GET https://localhost:9443/healthz
[Options]
insecure: true
HTTP 200

GET https://localhost:9443/ready
[Options]
insecure: true
HTTP 200

# Only the non-skipped path is present
GET http://localhost:9081/named_matcher.log
HTTP 200
[Asserts]
body contains "\"uri\":\"/named-api\""
body not contains "\"uri\":\"/healthz\""
body not contains "\"uri\":\"/ready\""
