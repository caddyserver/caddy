#!/usr/bin/env bash

set -euo pipefail
# if no files match glob, assume empty list instead of string literal
shopt -s nullglob

: ${build_package:="github.com/mholt/caddy"}

: ${dist_dir:="${GOPATH}/src/${build_package}/dist"}
: ${build_dir:="${dist_dir}/builds"}
: ${target_dir:="${dist_dir}/release"}

# Bundles a single binary, given as first parameter, into an archive.
package() {
  # Binary inside the zip file is simply the project name
  binbase="$(basename "${build_package}")"
  if [[ "${1}" == *.exe ]]; then
    binbase+=".exe"
  fi
  bin="${build_dir}/${binbase}"

  # Name .zip file same as binary, but strip .exe from end
  zipname="$(basename "${1%.exe}")"
  case "$(printf "${zipname}" | cut -d '_' -f 2 | sed -e 's:[a-z]*bsd:bsd:')" in
    linux|bsd) zipname+=".tar.gz" ;;
    *)         zipname+=".zip" ;;
  esac

  # Compress distributable depending on extension
  case "${zipname##*.}" in
    zip)
      zip -j "${target_dir}/${zipname}" \
        "${1}" \
        "${dist_dir}"/{CHANGES.txt,LICENSES.txt,README.txt}
      printf "@ $(basename "${1}")\n@=${binbase}\n" \
      | zipnote -w "${target_dir}/${zipname}"
      ;;
    gz)
      tar -caf "${target_dir}/${zipname}" \
        --owner=0 --group=0 \
        --transform="s#$(basename "${1}")#${binbase}#" \
        -C "$(dirname "${1}")" "$(basename "${1}")" \
        -C "${dist_dir}" CHANGES.txt LICENSES.txt README.txt
      ;;
  esac
}

prepare_directories() {
  mkdir -p "${build_dir}"
  rm -f "${build_dir}"/caddy*

  mkdir -p "${target_dir}"
  rm -f "${target_dir}"/caddy*
}

compile_binaries() {
  (cd "${build_dir}"; gox "${build_package}")
}

if [[ "${1:-}" == "" ]]; then
  prepare_directories
  compile_binaries

  case "${OSTYPE}" in
    linux*)
      find "${build_dir}" -type f -executable -print0 \
      | xargs --null --max-args=1 --max-procs=$(nproc --ignore=1) -I '{}' \
        "${0}" package '{}'
      ;;
    *)
      while read f; do
        package "${f}"
      done < <(ls -1 "${build_dir}"/caddy*)
      ;;
  esac
else
  ${1} "${2}"
fi
