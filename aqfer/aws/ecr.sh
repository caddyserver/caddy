#!/usr/bin/env bash
# set -e

docker build -t $2-caddy -f aqfer/Dockerfile .
aws ecr create-repository --region $1 --repository-name ecr-$2$3 --profile $4 > /tmp/ecrUri
aws ecr describe-repositories --region $1 --repository-name ecr-$2$3 --profile $4 > /tmp/ecrUri
ecrRepoUri=$(cat /tmp/ecrUri | sed -n "N;s/.*repositoryUri.*\"\(.*\)\".*/\1/p")
aws ecr get-login --region $1 --no-include-email --profile $4 | sed 's/docker login -u AWS -p \([^ ]*\) .*/\1/' | docker login -u AWS --password-stdin $ecrRepoUri
docker tag $2-caddy:latest $ecrRepoUri
docker push $ecrRepoUri
printf $ecrRepoUri > /tmp/ecrUri
