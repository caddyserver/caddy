#!/usr/bin/env bash
# set -e

aws ec2 create-key-pair --key-name $1 > /tmp/keypair
if grep -Fq "KeyMaterial" /tmp/keypair
then
  cat /tmp/keypair | sed -n "N;s/.*KeyMaterial.*\"\(.*\)\".*/\1/p" > aqfer/aws/$1.pem
  perl -pi -e 's/\\n/\n/g' aqfer/aws/$1.pem
  chmod 700 aqfer/aws/$1.pem
fi
