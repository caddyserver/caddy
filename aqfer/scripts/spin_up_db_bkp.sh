#!/usr/bin/env bash
# set -e

# aws cloudformation package --template-file /db_template_app_spec.yml --output-template-file /db_app_spec.yml --s3-bucket $1
# aws cloudformation deploy --template-file /db_app_spec.yml --stack-name $2 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
aws cloudformation package --template-file /ec_template_app_spec.yml --output-template-file /ec_app_spec.yml --s3-bucket $1
# aws cloudformation deploy --template-file /ec_app_spec.yml --stack-name $2 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset --parameter-overrides \
#  ECSecurityGroupName=$ECSecurityGroupName \
#  ECSubnetGroupName=$ECSubnetGroupName \
#  ECNodeType=$ECNodeType \
#  ECClusterName=$ECClusterName

  # DynamoTableName=$DynamoTableName \
  # PartitionKey=$PartitionKey \
  # SortKey=$SortKey \
  # DaxName=$DaxName \
  # DaxNodeType=$DaxNodeType \
  # DaxRoleName=$DaxRoleName \
  # DaxSubnetGroupName=$DaxSubnetGroupName \
  # DaxSecurityGroupName=$DaxSecurityGroupName \

aws s3 cp /ec_app_spec.yml s3://$ArtifactBucket/template/ec_app_spec.yml
#aws cloudformation create-stack-set --stack-set-name $2 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
#    --template-url https://s3.amazonaws.com/$ArtifactBucket/template/ec_app_spec.yml \
#    --parameters \
#        ParameterKey=ECSecurityGroupName,ParameterValue=$ECSecurityGroupName \
#        ParameterKey=ECSubnetGroupName,ParameterValue=$ECSubnetGroupName \
#        ParameterKey=ECNodeType,ParameterValue=$ECNodeType \
#        ParameterKey=ECClusterName,ParameterValue=$ECClusterName
aws cloudformation create-stack-instances --stack-set-name $2 --accounts 914664294701 --regions `echo $StackRegions | sed 's/,/ /g'` --operation-id $ECClusterName-create --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1
aws cloudformation describe-stack-set-operation --stack-set-name $2 --operation-id $ECClusterName-create