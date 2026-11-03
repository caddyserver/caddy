#!/usr/bin/env bash
# Prints the tag of the closest published (non-draft) GitHub release that is
# an ancestor of the given commit, or nothing if there is none.
#
# Usage: previous-release.sh <commit-ish> [tag-to-exclude]
#
# Release changelogs should cover everything since the last release users
# actually received. "The last tag" is not good enough: when a release attempt
# is abandoned after tagging, the Go module proxy has usually cached the tag,
# so it can't be deleted and reused, and the next attempt gets a new patch
# number. Those abandoned tags never get a published release, so they are
# skipped here. Only releases reachable from the commit count, so a release
# cut from a maintenance branch doesn't affect changelogs on master and vice
# versa.
#
# Requires GH_TOKEN and GITHUB_REPOSITORY in the environment (both are set in
# GitHub Actions when GH_TOKEN is passed explicitly), and full git history
# with tags.
set -euo pipefail

target=$(git rev-parse --verify "${1:?usage: $0 <commit-ish> [tag-to-exclude]}^{commit}")
exclude=${2:-}

# Releases are listed newest first, so on a tie (several published releases
# at the same distance) the most recently created one wins.
tags=$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases" --jq '.[] | select(.draft | not) | .tag_name')

best=""
best_distance=""
while IFS= read -r tag; do
	if [ -z "$tag" ] || [ "$tag" = "$exclude" ]; then
		continue
	fi
	if ! git rev-parse -q --verify "refs/tags/${tag}^{commit}" >/dev/null; then
		continue
	fi
	if ! git merge-base --is-ancestor "refs/tags/${tag}" "$target"; then
		continue
	fi
	distance=$(git rev-list --count "refs/tags/${tag}..${target}")
	if [ -z "$best" ] || [ "$distance" -lt "$best_distance" ]; then
		best=$tag
		best_distance=$distance
	fi
done <<< "$tags"

echo "$best"
