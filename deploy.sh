#!/usr/bin/env bash

set -e
set -x

# PROJECT, WORKSPACE are provided by jenkins

export BASEDIR="$WORKSPACE/src/github.com/startsmartlabs/caddy"
cd ${BASEDIR}

export AWS_DEFAULT_REGION=us-east-1
export STAGE=preprod

echo ${SERVICE_VERSION} > /tmp/serviceVersion
export VERSION=${SERVICE_VERSION}
go get ./...

#cversion=`build-tool -operation getcurrentversion -projecttype aio -versionurl http://imds.api-preprod.aqfer.net/version`
#set +x;printf "#----------------------------\n# current version : ${cversion}\n#----------------------------\n";set -x

make -f MakefileNew docker_aws_setup
#make -f MakefileCreatePreprod setup
make -f MakefileCreatePreprod update_tasks

# to avoid dial tcp i/o timeout
sleep 5
make -f MakefileCreatePreprod sanity
