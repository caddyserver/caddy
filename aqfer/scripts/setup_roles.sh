#!/usr/bin/env bash
# set -e

aws cloudformation package --template-file /iam_template_app_spec.yml --output-template-file /iam_app_spec.yml --s3-bucket $1
aws cloudformation deploy --template-file /iam_app_spec.yml --stack-name $2 --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --parameter-overrides \
  EC2InstanceRoleName=$EC2InstanceRoleName \
  ECSServiceRoleName=$ECSServiceRoleName \
  EC2InstanceProfileName=$EC2InstanceProfileName \
  ECRRepoName=$ECRRepoName \

