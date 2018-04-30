#!/usr/bin/env bash
# set -e

aws cloudformation package --template-file /ecs_template_app_spec.yml --output-template-file /ecs_app_spec.yml --s3-bucket $1
aws cloudformation deploy --template-file /ecs_app_spec.yml --stack-name $2 --region $StackRegion --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
  Id=$AWS_ACCESS_KEY_ID \
  Secret=$AWS_SECRET_ACCESS_KEY \
  Jwt=$Jwt \
  KeyPair=$KeyPair \
  LoadBalancerName=$LoadBalancerName \
  LBSecurityGroupName=$LBSecurityGroupName \
  TargetGroupName=$TargetGroupName \
  EC2InstanceType=$EC2InstanceType \
  EC2SecurityGroupName=$EC2SecurityGroupName \
  EC2InstanceProfileName=$EC2InstanceProfileName \
  ECSClusterName=$ECSClusterName \
  ECSServiceRoleName=$ECSServiceRoleName \
  ECSServiceName=$ECSServiceName \
  ECSTaskDefinitionName=$ECSTaskDefinitionName \
  ECSTaskCount=$ECSTaskCount \
  ECRRepoName=$ECRRepoName \
  ECRRepoRegion=$ECRRepoRegion \
  ImageVersion=$ImageVersion \
  ContainerName=$ContainerName \
  AppLogGroupName=$AppLogGroupName \
  ECSLogGroupName=$ECSLogGroupName \
  DomainCertificateId=$DomainCertificateId \
  ServiceStage=$ServiceStage \
  ECSecurityGroupName=$3 \
  ECInboundProtocol=tcp \
  ECStackName=$ECStackName

# Dax security group ingress from ec2 security group
# aws ec2 authorize-security-group-ingress --group-name $5 --source-group $EC2SecurityGroupName --port $6 --protocol tcp
