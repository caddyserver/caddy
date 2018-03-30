#!/usr/bin/env bash
# set -e

aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email > /tmp/ecrLogin
login=$(cat /tmp/ecrLogin | sed -E "s/docker login -u AWS -p ([^ ]*) .*/\1/")
echo $login
