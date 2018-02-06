#!/usr/bin/env bash
# set -e

cd /go/src/github.com/fellou89/caddy-awscloudwatch/
go test
cd /go/src/github.com/fellou89/caddy-cache/
go test
cd /go/src/github.com/fellou89/caddy-reauth/backends/refresh/
go test
cd /go/src/github.com/fellou89/caddy-redis/unit_tests/
go test
cd /go/src/github.com/fellou89/caddy-secrets/unit_tests/
go test
