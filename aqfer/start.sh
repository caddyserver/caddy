#!/usr/bin/env bash

ID=$(aws --profile default configure get aws_access_key_id)
SECRET=$(aws --profile default configure get aws_secret_access_key)
REGION=$(aws --profile default configure get region)
JWT=testkey

ID=$ID SECRET=$SECRET REGION=$REGION JWT=$JWT docker-compose up

# docker run -p 8082:8082 -e AWS_ACCESS_KEY_ID=$ID -e AWS_SECRET_ACCESS_KEY=$SECRET -e AWS_REGION=$REGION -e JWT_SECRET=$JWT aqfer-caddy $1
