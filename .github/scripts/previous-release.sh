#!/usr/bin/env bash
# Prints the tag of the highest published (non-draft) GitHub release whose
# version is lower than the given one, or nothing if there is none.
#
# Usage: previous-release.sh <version>
#
# Release changelogs should cover everything since the last release users
# actually received. "The last tag" is not good enough:
#
#   - When a release attempt is abandoned after tagging, the Go module proxy
#     has usually cached the tag, so it can't be deleted and reused, and the
#     next attempt gets a new patch number. Those abandoned tags never get a
#     published release, so they are skipped here.
#   - Releases can be cut from maintenance branches (e.g. 2.11), so the
#     previous release isn't necessarily an ancestor of the new one. Picking
#     by version means 2.12.0 compares against the latest 2.11.x, and a 2.11.x
#     released after 2.12.0 compares against the previous 2.11.x.
#
# Requires GH_TOKEN and GITHUB_REPOSITORY in the environment.
set -euo pipefail

version=${1:?usage: $0 <version>}

# sort -V orders "2.12.0-beta.1" after "2.12.0", but with the prerelease
# separator replaced by "~" (which sorts before everything, even the end of
# the string) it orders like semver.
sort_key() {
	printf '%s' "${1#v}" | sed 's/-/~/'
}

tags=$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases" --jq '.[] | select(.draft | not) | .tag_name')

{
	# The new version itself, marked by an empty tag column.
	printf '%s\t\n' "$(sort_key "$version")"
	grep -E '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' <<< "$tags" | while IFS= read -r tag; do
		if [ "$tag" != "$version" ]; then
			printf '%s\t%s\n' "$(sort_key "$tag")" "$tag"
		fi
	done
} | sort -t $'\t' -k1,1V | awk -F '\t' '$2 == "" { print prev; exit } { prev = $2 }'
