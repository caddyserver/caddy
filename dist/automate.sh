#!/usr/bin/env bash
set -e
set -o pipefail
shopt -s nullglob # if no files match glob, assume empty list instead of string literal


## PACKAGE TO BUILD
Package=github.com/mholt/caddy


## PATHS TO USE
DistDir=$GOPATH/src/$Package/dist
BuildDir=$DistDir/builds
ReleaseDir=$DistDir/release


## BEGIN

# Compile binaries
mkdir -p $BuildDir
cd $BuildDir
rm -f *
gox $Package

# Zip them up with release notes and stuff
mkdir -p $ReleaseDir
cd $ReleaseDir
rm -f *
for f in $BuildDir/*
do
	# Name .zip file same as binary, but strip .exe from end
	zipname=$(basename ${f%".exe"}).zip

	# Binary inside the zip file is simply the project name
	bin=$BuildDir/$(basename $Package)
	if [[ $f == *.exe ]]
	then
		bin=$bin.exe
	fi
	mv $f $bin

	# Compress distributable
	zip -j $zipname $bin $DistDir/CHANGES.txt $DistDir/LICENSES.txt $DistDir/README.txt

	# Put binary filename back to original
	mv $bin $f
done
