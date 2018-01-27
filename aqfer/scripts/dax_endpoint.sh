#!/usr/bin/env bash
# set -e

aws dax describe-clusters --cluster-names $1 > /tmp/dax_cluster
daxAddress=$(cat /tmp/dax_cluster | perl -pe 's|[\n\s]+|=|g' | sed -n -E "s#.*ClusterDiscoveryEndpoint\":=\{[^\}]*\"Address\":=\"([^\"]*)\".*#\1#p")
daxPort=$(cat /tmp/dax_cluster | perl -pe 's|[\n\s]+|=|g' | sed -n -E "s#.*ClusterDiscoveryEndpoint\":=\{[^\}]*\"Port\":=([0-9]*).*#\1#p")
echo $daxAddress':'$daxPort
