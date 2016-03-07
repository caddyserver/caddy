#!/usr/bin/env bash
#
# Caddy build script. Automates proper versioning.
#
# Usage:
#
#     $ ./build.bash [output_filename]
#
# Outputs compiled program in current directory.
# Default file name is 'ecaddy'.
#
set -e

output="$1"
if [ -z "$output" ]; then
	output="ecaddy"
fi

pkg=main

# Timestamp of build
builddate_id=$pkg.buildDate
builddate=`date -u`

# Current tag, if HEAD is on a tag
tag_id=$pkg.gitTag
set +e
tag=`git describe --exact-match HEAD 2> /dev/null`
set -e

# Nearest tag on branch
lasttag_id=$pkg.gitNearestTag
lasttag=`git describe --abbrev=0 --tags HEAD`

# Commit SHA
commit_id=$pkg.gitCommit
commit=`git rev-parse --short HEAD`

# Summary of uncommited changes
shortstat_id=$pkg.gitShortStat
shortstat=`git diff-index --shortstat HEAD`

# List of modified files
files_id=$pkg.gitFilesModified
files=`git diff-index --name-only HEAD`


go build -ldflags "
	-X \"$builddate_id=$builddate\"
	-X \"$tag_id=$tag\"
	-X \"$lasttag_id=$lasttag\"
	-X \"$commit_id=$commit\"
	-X \"$shortstat_id=$shortstat\"
	-X \"$files_id=$files\"
" -o "$output"
