set -e
set -x

export STAGE=preprod
export AWS_DEFAULT_REGION=us-east-1

# PROJECT, WORKSPACE are provided by jenkins

go get -u "github.com/caddyserver/builds" "github.com/startsmartlabs/caddy-secrets" "github.com/startsmartlabs/caddy-transformrequest" "github.com/startsmartlabs/caddy-transformresponse" "github.com/startsmartlabs/caddy-redis" "github.com/startsmartlabs/caddy-awscloudwatch" "github.com/startsmartlabs/aqfer-io-custom-handler-api"

export MAJOR_VERSION=`make -f MakefileCreatePreprod get_major_version`
echo $MAJOR_VERSION
export VERSION=`make -f MakefileCreatePreprod get_next_version`
echo $VERSION

make -f MakefileCreatePreprod aws_build ecr_repo_push
