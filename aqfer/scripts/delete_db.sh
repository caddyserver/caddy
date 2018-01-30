#!/usr/bin/env bash
# set -e

# aws elasticache delete-cache-cluster --cache-cluster-id ${EC_CLUSTER_NAME}
# aws elasticache delete-cache-subnet-group --cache-subnet-group-name ${EC_SUBNET_GROUP}
aws cloudformation delete-stack --stack-name $1
