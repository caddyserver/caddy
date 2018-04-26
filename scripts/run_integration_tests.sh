#!/usr/bin/env bash
# set -e

# cd integration_tests/secrets_reauth/
# go test
# cd integration_tests/reauth_transformrequest/
# go test
cd integration_tests/transformrequest_redis
go test
