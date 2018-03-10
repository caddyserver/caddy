#!/usr/bin/env bash
# set -e

cd /go/src/github.com/fellou89/caddy-cache/
go test
cd /go/src/github.com/fellou89/caddy-reauth/backends/refresh/
go test
cd /go/src/github.com/startsmartlabs/caddy-secrets/
go test
cd /go/src/github.com/startsmartlabs/caddy-awscloudwatch/
go test
cd /go/src/github.com/startsmartlabs/caddy-redis/
go test
