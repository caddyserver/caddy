module local.tld/fuzz

go 1.12

replace github.com/caddyserver/caddy/v2 => ./..

require (
	github.com/caddyserver/caddy/v2 v2.0.0-00010101000000-000000000000
	github.com/dvyukov/go-fuzz v0.0.0-20190819180756-98cec4f75045
)
