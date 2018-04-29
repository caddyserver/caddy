#!/usr/bin/env bash
# set -e

cd integration_tests/secrets_reauth/
go test
cd integration_tests/reauth_transformrequest/
go test
cd integration_tests/request_to_response
go test
cd integration_tests/end_to_end
go test
