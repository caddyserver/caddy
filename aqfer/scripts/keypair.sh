#!/usr/bin/env bash
# set -e

aws ec2 create-key-pair --key-name $1 > /tmp/keypair
if grep -Fq "KeyMaterial" /tmp/keypair
then
  cat /tmp/keypair | sed -n "N;s/.*KeyMaterial.*\"\(.*\)\".*/\1/p" > $1.pem
  perl -pi -e 's/\\n/\n/g' $1.pem
  cat $1.pem
fi
