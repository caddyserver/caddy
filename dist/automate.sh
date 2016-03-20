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
rm -f caddy*
gox $Package

# Zip them up with release notes and stuff
mkdir -p $ReleaseDir
cd $ReleaseDir
rm -f caddy*
for f in $BuildDir/*
do
	# Name .zip file same as binary, but strip .exe from end
	zipname=$(basename ${f%".exe"})
	if [[ $f == *"linux"* ]] || [[ $f == *"bsd"* ]]; then
		zipname=${zipname}.tar.gz
	else
		zipname=${zipname}.zip
	fi

	# Binary inside the zip file is simply the project name
	binbase=$(basename $Package)
	if [[ $f == *.exe ]]; then
		binbase=$binbase.exe
	fi
	bin=$BuildDir/$binbase
	mv $f $bin

	# Compress distributable
	if [[ $zipname == *.zip ]]; then
		zip -j $zipname $bin $DistDir/CHANGES.txt $DistDir/LICENSES.txt $DistDir/README.txt
	else
		tar -cvzf $zipname -C $BuildDir $binbase -C $DistDir CHANGES.txt LICENSES.txt README.txt
	fi

	# Put binary filename back to original
	mv $bin $f
done
