#!/usr/bin/env bash
# set -e

aws ec2 create-key-pair --key-name $1 --profile $2 > /tmp/keypair
if grep -Fxq "KeyMaterial" /tmp/keypair
then
  cat /tmp/keypair | sed -n "N;s/.*KeyMaterial.*\"\(.*\)\".*/\1/p" > $1.pem
  perl -pi -e 's/\\n/\n/g' $1.pem
  chmod 700 $1.pem
fi
