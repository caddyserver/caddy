#!/usr/bin/env bash
# set -e

# aws cloudformation package --template-file /db_template_app_spec.yml --output-template-file /db_app_spec.yml --s3-bucket $1
# aws cloudformation deploy --template-file /db_app_spec.yml --stack-name $2 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
aws cloudformation package --template-file /ec_template_app_spec.yml --output-template-file /ec_app_spec.yml --s3-bucket $1
aws cloudformation deploy --template-file /ec_app_spec.yml --stack-name $2 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
  AWSAccount=$AWSAccount \
  AvailabilityZone=$AvailabilityZone \
  Subnet=$Subnet \
  Vpc=$Vpc \
  ECSecurityGroupName=$ECSecurityGroupName \
  ECSubnetGroupName=$ECSubnetGroupName \
  ECNodeType=$ECNodeType \
  ECClusterName=$ECClusterName

  # DynamoTableName=$DynamoTableName \
  # PartitionKey=$PartitionKey \
  # SortKey=$SortKey \
  # DaxName=$DaxName \
  # DaxNodeType=$DaxNodeType \
  # DaxRoleName=$DaxRoleName \
  # DaxSubnetGroupName=$DaxSubnetGroupName \
  # DaxSecurityGroupName=$DaxSecurityGroupName \

