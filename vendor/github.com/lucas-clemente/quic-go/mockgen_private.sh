#!/bin/bash

# Mockgen refuses to generate mocks private types.
# This script copies the quic package to a temporary directory, and adds an public alias for the private type.
# It then creates a mock for this public (alias) type.

TEMP_DIR=$(mktemp -d)
mkdir -p $TEMP_DIR/src/github.com/lucas-clemente/quic-go/

# uppercase the name of the interface
INTERFACE_NAME="$(tr '[:lower:]' '[:upper:]' <<< ${4:0:1})${4:1}"

# copy all .go files to a temporary directory
rsync -r --exclude 'vendor' --include='*.go' --include '*/' --exclude '*'   $GOPATH/src/github.com/lucas-clemente/quic-go/ $TEMP_DIR/src/github.com/lucas-clemente/quic-go/

# create a public alias for the interface, so that mockgen can process it
echo -e "package $1\n" > $TEMP_DIR/src/github.com/lucas-clemente/quic-go/mockgen_interface.go
echo "type $INTERFACE_NAME = $4" >> $TEMP_DIR/src/github.com/lucas-clemente/quic-go/mockgen_interface.go

export GOPATH="$TEMP_DIR:$GOPATH"

mockgen -package $1 -self_package $1 -destination $2 $3 $INTERFACE_NAME

# mockgen imports quic-go as 'import quic_go github.com/lucas_clemente/quic-go'
sed -i '' 's/quic_go.//g' $2
goimports -w $2

rm -r "$TEMP_DIR"
