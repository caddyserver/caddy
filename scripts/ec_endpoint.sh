#!/usr/bin/env bash
# set -e

aws elasticache describe-cache-clusters --cache-cluster-id $1 --show-cache-node-info > /tmp/ec_cluster
ecAddress=$(cat /tmp/ec_cluster | perl -pe 's|[\n\s]+|=|g' | sed -n -E "s#.*Endpoint\":=\{[^\}]*\"Address\":=\"([^\"]*)\".*#\1#p")
ecPort=$(cat /tmp/ec_cluster | perl -pe 's|[\n\s]+|=|g' | sed -n -E "s#.*Endpoint\":=\{[^\}]*\"Port\":=([0-9]*).*#\1#p")
echo $ecAddress':'$ecPort
