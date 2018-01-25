#!/usr/bin/env bash
# set -e

DBVERSION=2
ECSVERSION=3
ROOT_NAME=aqfer

# AWS_ACCOUNT='545654232789'
# AWS_PROFILE=default
AWS_ACCOUNT='392630614516'
AWS_PROFILE=default

ID=$(aws configure get aws_access_key_id --profile $AWS_PROFILE)
SECRET=$(aws configure get aws_secret_access_key --profile $AWS_PROFILE)
REGION=$(aws configure get region --profile $AWS_PROFILE)
JWT=testkey

AMI=ami-832b1cf9
# AMI=ami-fad25980 # ecs optimized ami
INSTANCE_TYPE=t2.medium
# INSTANCE_TYPE=c5.large
VPC=vpc-5a340c22
SUBNET=subnet-867f59cd
SUBNET2=subnet-2cba2771
ZONE=us-east-1a
KEYPAIR_NAME=AqferKeyPair
APP_LOG_GROUP_NAME=aqfer.io

EC_SECURITY_GROUP=$ROOT_NAME'EC-sg'$DBVERSION
EC_CLUSTER_NAME=elasticache$ROOT_NAME$DBVERSION
EC_NODE_TYPE=cache.m4.large
DAX_SECURITY_GROUP=$ROOT_NAME'DAX-sg'$DBVERSION
DAX_CLUSTER_NAME=dax$ROOT_NAME$DBVERSION
DAX_NODE_TYPE=dax.r3.large
DYNAMO_TABLE=$ROOT_NAME-idsync$DBVERSION
PARTITION_KEY='partition-key'
SORT_KEY='sort-key'

TASK_DEFINITION=$ROOT_NAME'TaskDefinition'$ECSVERSION
ECS_LOG_GROUP_NAME=/ecs/$TASK_DEFINITION
ECS_SERVICE=$ROOT_NAME'Service'$ECSVERSION
EC2_SECURITY_GROUP=$ROOT_NAME'EC2-sg'$ECSVERSION
LOAD_BALANCER_NAME=$ROOT_NAME'LoadBalancer'$ECSVERSION
LB_SECURITY_GROUP=$ROOT_NAME'LB-sg'$ECSVERSION


# bucket name must be all lowercase, and start/end with lowecase letter or number
ARTIFACTS_BUCKET=cloudformation-art-$ROOT_NAME
if false
then
  # Create cloudformation bucket
  aws s3 mb s3://$ARTIFACTS_BUCKET/ --region $REGION --profile $AWS_PROFILE
  
  # Create key pair
  bash ./aqfer/aws/keypair.sh $KEYPAIR_NAME $AWS_PROFILE
fi

   
# launch db
if false
then
  aws cloudformation package --template-file aqfer/aws/db_template_app_spec.yml --output-template-file aqfer/aws/db_app_spec.yml \
    --s3-bucket $ARTIFACTS_BUCKET --profile $AWS_PROFILE
  aws cloudformation deploy --template-file aqfer/aws/db_app_spec.yml --stack-name 'DB'$ROOT_NAME$DBVERSION \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --profile $AWS_PROFILE --parameter-overrides \
    AWSAccount=$AWS_ACCOUNT \
    AvailabilityZone=$ZONE \
    Subnet=$SUBNET \
    Vpc=$VPC \
    DynamoTableName=$DYNAMO_TABLE \
    PartitionKey=$PARTITION_KEY \
    SortKey=$SORT_KEY \
    DaxName=$DAX_CLUSTER_NAME \
    DaxNodeType=$DAX_NODE_TYPE \
    DaxRoleName=$ROOT_NAME'DaxRole'$DBVERSION \
    DaxSubnetGroupName=dax-subnet-$ROOT_NAME$DBVERSION \
    DaxSecurityGroupName=$DAX_SECURITY_GROUP \
    ECSecurityGroupName=$EC_SECURITY_GROUP \
    ECSubnetGroupName=elasticache-subnet-$ROOT_NAME$DBVERSION \
    ECNodeType=$EC_NODE_TYPE \
    ECClusterName=$EC_CLUSTER_NAME
fi


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


# push repo
if true
then
  # Currently set to 0 so that only one ECS repo is used, but could use VERSION as param instead
  bash ./aqfer/aws/ecr.sh $REGION $ROOT_NAME 0 $AWS_PROFILE
fi
ECRRepoURI=$(cat /tmp/ecrUri)


# launch ecs
if false
then
  aws cloudformation package --template-file aqfer/aws/ecs_template_app_spec.yml --output-template-file aqfer/aws/ecs_app_spec.yml \
  --s3-bucket $ARTIFACTS_BUCKET --profile $AWS_PROFILE
  aws cloudformation deploy --template-file aqfer/aws/ecs_app_spec.yml --stack-name 'ECS'$ROOT_NAME$ECSVERSION \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --profile $AWS_PROFILE --parameter-overrides \
    Id=$ID \
    Secret=$SECRET \
    Jwt=$JWT \
    AWSAccount=$AWS_ACCOUNT \
    Ami=$AMI \
    Subnet=$SUBNET \
    Subnet2=$SUBNET2 \
    Vpc=$VPC \
    AvailabilityZone=$ZONE \
    KeyPair=$KEYPAIR_NAME \
    LoadBalancerName=$LOAD_BALANCER_NAME \
    LBSecurityGroupName=$LB_SECURITY_GROUP \
    TargetGroupName=$ROOT_NAME'TargetGroup'$ECSVERSION \
    EC2InstanceType=$INSTANCE_TYPE \
    EC2SecurityGroupName=$EC2_SECURITY_GROUP \
    EC2InstanceRoleName=$ROOT_NAME'EC2InstanceRole'$ECSVERSION \
    ECSClusterName=$ROOT_NAME'Cluster'$ECSVERSION \
    ECSServiceRoleName=$ROOT_NAME'ECSServiceRole'$ECSVERSION \
    ECSTaskDefinitionName=$TASK_DEFINITION \
    ECSServiceName=$ROOT_NAME'Service'$ECSVERSION \
    ECRRepoURI=$ECRRepoURI \
    ContainerName=$ROOT_NAME-caddy \
    AppLogGroupName=$APP_LOG_GROUP_NAME \
    ECSLogGroupName=$ECS_LOG_GROUP_NAME

  aws ec2 authorize-security-group-ingress --group-name $EC_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $ecPort --protocol tcp --profile $AWS_PROFILE
  aws ec2 authorize-security-group-ingress --group-name $DAX_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $daxPort --protocol tcp --profile $AWS_PROFILE

  aws elbv2 describe-load-balancers --names $LOAD_BALANCER_NAME --profile $AWS_PROFILE > /tmp/DNSName
  dnsName=$(cat /tmp/DNSName | sed -n "s/.*\"DNSName\".*\"\(.*\)\",/\1/p")
  echo 'Endpoint: '$dnsName
fi

# deletes ecs stack, needs to disconnect security groups first
instanceIds='i-06e2cef6dadb3bea8'
if false
then
  aws ec2 revoke-security-group-ingress --group-name $EC_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $ecPort --protocol tcp --profile $AWS_PROFILE
  aws ec2 revoke-security-group-ingress --group-name $DAX_SECURITY_GROUP --source-group $EC2_SECURITY_GROUP \
    --port $daxPort --protocol tcp --profile $AWS_PROFILE

  aws ec2 terminate-instances --instance-ids $instanceIds --profile $AWS_PROFILE
  aws ec2 wait instance-terminated --instance-ids $instanceIds --profile $AWS_PROFILE

  aws cloudformation delete-stack --stack-name 'ECS'$ROOT_NAME$ECSVERSION --profile $AWS_PROFILE
fi
