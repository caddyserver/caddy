#!/usr/bin/env bash
# set -e

DBVERSION=2
ECSVERSION=1
ROOT_NAME=aqfer

AWS_ACCOUNT='392630614516'
AWS_PROFILE=default

ID=$(aws configure get aws_access_key_id --profile $AWS_PROFILE)
SECRET=$(aws configure get aws_secret_access_key --profile $AWS_PROFILE)
REGION=$(aws configure get region --profile $AWS_PROFILE)
JWT=testkey

VPC=vpc-5a340c22
SUBNET=subnet-867f59cd
KEYPAIR_NAME=AqferKeyPair
APP_LOG_GROUP_NAME=aqfer.io

EC_SECURITY_GROUP=$ROOT_NAME'EC-sg'$DBVERSION
EC_CLUSTER_NAME=elasticache$ROOT_NAME$DBVERSION
DAX_SECURITY_GROUP=$ROOT_NAME'DAX-sg'$DBVERSION
DAX_CLUSTER_NAME=dax$ROOT_NAME$DBVERSION
DYNAMO_TABLE=$ROOT_NAME-idsync$DBVERSION
PARTITION_KEY='partition-key'
SORT_KEY='sort-key'

TASK_DEFINITION=$ROOT_NAME'TaskDefinition'$ECSVERSION
ECS_LOG_GROUP_NAME=/ecs/$TASK_DEFINITION
ECS_CLUSTER_NAME=$ROOT_NAME'Cluster'$ECSVERSION
EC2_SECURITY_GROUP=$ROOT_NAME'EC2-sg'$ECSVERSION
EC2_INSTANCE_TYPE=c5.large
# EC2_INSTANCE_TYPE=t2.medium


ARTIFACTS_BUCKET=cloudformation-art-$ROOT_NAME


aws elasticache describe-cache-clusters --cache-cluster-id $EC_CLUSTER_NAME --show-cache-node-info --profile $AWS_PROFILE > /tmp/ec_cluster
ecPort=$(cat /tmp/ec_cluster | sed -n "N;s/.*Port.*: \(.*\),.*/\1/p")
ecAddress=$(cat /tmp/ec_cluster | sed -n "N;s/.*Address.*\"\(.*\)\".*/\1/p")
EC_ENDPOINT=$ecAddress':'$ecPort

aws dax describe-clusters --cluster-names $DAX_CLUSTER_NAME --profile $AWS_PROFILE > /tmp/dax_cluster
daxPort=$(cat /tmp/dax_cluster | sed -n "N;s/.*ClusterDiscoveryEndpoint.*\n.*Port.*: \(.*\),.*/\1/p")
daxAddress=$(cat /tmp/dax_cluster | sed -n "N;N;s/.*ClusterDiscoveryEndpoint.*\n.*\n.*Address.*: \"\(.*\)\"/\1/p")
DAX_ENDPOINT=$daxAddress':'$daxPort

cat aqfer/Caddyfile_template | sed 's/APP_LOG_GROUP_NAME/'$APP_LOG_GROUP_NAME'/g' > /tmp/Caddyfile
perl -pi -e 's/DYNAMO_TABLE/'$DYNAMO_TABLE'/g' /tmp/Caddyfile
perl -pi -e 's/PARTITION_KEY/'$PARTITION_KEY'/g' /tmp/Caddyfile
perl -pi -e 's/SORT_KEY/'$SORT_KEY'/g' /tmp/Caddyfile
perl -pi -e 's/EC_ENDPOINT/'$EC_ENDPOINT'/g' /tmp/Caddyfile
cat /tmp/Caddyfile | sed 's/DAX_ENDPOINT/'$DAX_ENDPOINT'/g' > aqfer/Caddyfile

# create ecr repo
if false
then
  bash ./aqfer/aws/ecr.sh $REGION $ROOT_NAME 0 $AWS_PROFILE
fi
ECRRepoURI=$(cat /tmp/ecrUri)

if false
then
  aws ecs list-tasks --cluster $ECS_CLUSTER_NAME --profile $AWS_PROFILE > /tmp/task_definition
  taskId1=$(cat /tmp/task_definition | sed -n "N;N;s/.*taskArns.*\n.*\"\(.*\)\".*/\1/p")
  # taskId2=$(cat /tmp/task_definition | sed -n "N;N;N;s/.*taskArns.*\n.*\n.*\"\(.*\)\".*/\1/p")

  aws ecs stop-task --cluster $ECS_CLUSTER_NAME --task $taskId1 --profile $AWS_PROFILE
  aws ecs stop-task --cluster $ECS_CLUSTER_NAME --task $taskId2 --profile $AWS_PROFILE

  bash ./aqfer/aws/ecr.sh $REGION $ROOT_NAME 0 $AWS_PROFILE

  aws ecs run-task --cluster $ECS_CLUSTER_NAME --task-definition $TASK_DEFINITION':22' --region $REGION --profile $AWS_PROFILE
  aws ecs run-task --cluster $ECS_CLUSTER_NAME --task-definition $TASK_DEFINITION':23' --region $REGION --profile $AWS_PROFILE
fi

if false
then
  aws cloudformation package --template-file aqfer/aws/dev_template_app_spec.yml --output-template-file aqfer/aws/dev_app_spec.yml \
  --s3-bucket $ARTIFACTS_BUCKET --profile $AWS_PROFILE
  aws cloudformation deploy --template-file aqfer/aws/dev_app_spec.yml --stack-name 'ECS'$ROOT_NAME$ECSVERSION \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --profile $AWS_PROFILE --parameter-overrides \
    Id=$ID \
    Secret=$SECRET \
    Jwt=$JWT \
    AWSAccount=$AWS_ACCOUNT \
    Subnet=$SUBNET \
    Vpc=$VPC \
    KeyPair=$KEYPAIR_NAME \
    EC2InstanceType=$EC2_INSTANCE_TYPE \
    EC2SecurityGroupName=$EC2_SECURITY_GROUP \
    EC2InstanceRoleName=$ROOT_NAME'EC2InstanceRole'$ECSVERSION \
    ECSClusterName=$ECS_CLUSTER_NAME \
    ECSTaskDefinitionName=$TASK_DEFINITION \
    ECRRepoURI=$ECRRepoURI \
    ContainerName=$ROOT_NAME-caddy \
    AppLogGroupName=$APP_LOG_GROUP_NAME \
    ECSLogGroupName=$ECS_LOG_GROUP_NAME

  aws ec2 authorize-security-group-ingress --group-name $EC_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $ecPort --protocol tcp --profile $AWS_PROFILE
  aws ec2 authorize-security-group-ingress --group-name $DAX_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $daxPort --protocol tcp --profile $AWS_PROFILE
fi

instanceIds=''
if true
then
  aws ec2 revoke-security-group-ingress --group-name $EC_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $ecPort --protocol tcp --profile $AWS_PROFILE
  aws ec2 revoke-security-group-ingress --group-name $DAX_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $daxPort --protocol tcp --profile $AWS_PROFILE

  aws ec2 terminate-instances --instance-ids $instanceIds --profile $AWS_PROFILE
  aws ec2 wait instance-terminated --instance-ids $instanceIds --profile $AWS_PROFILE

  aws cloudformation delete-stack --stack-name 'ECS'$ROOT_NAME$ECSVERSION --profile $AWS_PROFILE
fi
