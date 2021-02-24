#!/bin/sh

# USAGE: go run -exec ./setcap.sh <args...>

sudo setcap cap_net_bind_service=+ep "$1"
"$@"
