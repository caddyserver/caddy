#!/usr/bin/env bash
# set -e

AWS_ACCOUNT='545654232789'
ID=$(aws --profile default configure get aws_access_key_id)
SECRET=$(aws --profile default configure get aws_secret_access_key)
REGION=$(aws --profile default configure get region)
JWT=testkey

VERSION=0
ROOT_NAME=aqfer
AMI=ami-55ef662f
#  AMI=ami-fad25980 # ecs optimized ami
KEYPAIR_NAME=AqferKeyPair

APP_NAME=$ROOT_NAME$VERSION
ECS_CLUSTER=$ROOT_NAME'Cluster'$VERSION
ECS_SERVICE=$ROOT_NAME'Service'$VERSION
EC2_INSTANCE_ROLE=$ROOT_NAME'EC2InstanceRole'$VERSION
TASK_DEFINITION=$ROOT_NAME'TaskDefinition'$VERSION
SECURITY_GROUP=$ROOT_NAME-sg$VERSION
DYNAMO_TABLE=$ROOT_NAME-idsync$VERSION

# Bucket name must be all lowercase, and start/end with lowecase letter or number
ARTIFACTS_BUCKET=cloudformation-art

# Create ecr repo for docker image
aws ecr create-repository --region $REGION --repository-name ecr-$ROOT_NAME'1' > /tmp/ecrUri
aws ecr describe-repositories --region $REGION --repository-name ecr-$ROOT_NAME'1' > /tmp/ecrUri
ecrRepoUri=$(cat /tmp/ecrUri | sed -n "N;s/.*repositoryUri.*\"\(.*\)\".*/\1/p")
aws ecr get-login --region $REGION --no-include-email | sed 's/docker login -u AWS -p \([^ ]*\) .*/\1/' | docker login -u AWS --password-stdin $ecrRepoUri
docker tag $ROOT_NAME-caddy:latest $ecrRepoUri
docker push $ecrRepoUri

# Create key pair
aws ec2 create-key-pair --key-name $KEYPAIR_NAME
   
#  # Create security group
#  aws ec2 create-security-group --group-name $SECURITY_GROUP
   
# Create cloudformation bucket
aws s3 mb s3://$ARTIFACTS_BUCKET/ --region $REGION
   
# Launch cloudformation stack
aws cloudformation package --template-file template_app_spec.yml --output-template-file app_spec.yml --s3-bucket $ARTIFACTS_BUCKET
aws cloudformation deploy --template-file app_spec.yml --stack-name $APP_NAME --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
  Id=$ID \
  Secret=$SECRET \
  Jwt=$JWT \
  Version=$VERSION \
  RootName=$ROOT_NAME \
  AWSAccount=$AWS_ACCOUNT \
  Ami=$AMI \
  AppName=$APP_NAME \
  KeyPair=$KEYPAIR_NAME \
  SecurityGroupName=$SECURITY_GROUP \
  EC2InstanceRoleName=$EC2_INSTANCE_ROLE \
  ClusterName=$ECS_CLUSTER \
  TaskDefinitionName=$TASK_DEFINITION \
  ECRRepoURI=$ecrRepoUri \
  DynamoTableName=$DYNAMO_TABLE

 echo "App name: " $APP_NAME
