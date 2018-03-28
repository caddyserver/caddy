#!/usr/bin/env bash
# set -e

aws ecr create-repository --repository-name ecr-$1$2 1> /dev/null 2> /dev/null
aws ecr describe-repositories --repository-name ecr-$1$2 > /tmp/ecrResources
uri=$(cat /tmp/ecrResources | sed -E -n "s/.*repositoryArn.*\"(.*)\".*/\1/p")
echo $uri
