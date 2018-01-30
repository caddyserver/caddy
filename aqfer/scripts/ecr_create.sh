#!/usr/bin/env bash
# set -e

aws ecr create-repository --repository-name ecr-$1$2 2> /dev/null
aws ecr describe-repositories --repository-name ecr-$1$2 > /tmp/ecrUri
uri=$(cat /tmp/ecrUri | sed -E -n "s/.*repositoryUri.*\"(.*)\".*/\1/p")
echo $uri
