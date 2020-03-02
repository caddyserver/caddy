#!/bin/bash

# ------------------------------------------
# Caddy 2 build script
#
# Builds Caddy 2 from source with the
# proper embedded version information
#
# Optional arguments:
#  $destination Path to the resulting binary
#               (default: "./caddy")
#  $version     Version to build
#               (default: autodetected)
# ------------------------------------------

destination="${1:-./caddy}"
version="$2"

# resolve the destination to its actual absolute path
destination="$(cd "${destination%/*}" && echo "$PWD/${destination##*/}")"

if [[ -d "$destination" ]]; then
	echo -e "\033[1m🚫  Destination $destination is a directory,"
	echo -e "   please pass the full path to the destination file.\033[0m"
	exit 1
fi

# our working directory is always the
# cmd/caddy directory inside the repo
buildPath="$(dirname "$0")/cmd/caddy"
echo -e "\033[1m🛠  cd $buildPath\033[0m"
cd "$buildPath"

# try to determine the version from the Git repo if not given
if [[ -z "$version" ]]; then
	if tagVersion="$(git describe --exact-match HEAD 2>/dev/null)"; then
		version="$tagVersion"

		echo -e "\033[1m📍  Detected Caddy version as $tagVersion (tag)\033[0m"
	elif commitVersion="$(git rev-parse --short HEAD 2>/dev/null)"; then
		version="$commitVersion"

		echo -e "\033[1m📍  Detected Caddy version as $commitVersion (commit)\033[0m"
	else
		echo -e "\033[1m⚠️  Could not autodetect Caddy version, the binary won't have embedded version information."
	fi
fi

# exit on error of any of the following commands
set -e

# if we (now) have a version, initialize a Go module and fetch the correct version
if [[ -n "$version" ]]; then
	if [[ ! -e "go.mod" ]]; then
		echo -e "\033[1m🛠  go mod init caddy\033[0m"
		go mod init caddy
	fi

	echo -e "\033[1m🛠  go get \"github.com/caddyserver/caddy/v2@$version\"\033[0m"
	go get "github.com/caddyserver/caddy/v2@$version"
fi

# actual build
echo -e "\033[1m🛠  go build -o \"$destination\"\033[0m"
go build -o "$destination"

# cleanup
if [[ -n "$version" ]]; then
	echo -e "\033[1m🛠  rm go.mod go.sum\033[0m"
	rm go.mod go.sum
fi

echo -e "\033[1m🏁  $destination version\033[0m"
"$destination" version
