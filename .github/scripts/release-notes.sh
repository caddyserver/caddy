#!/usr/bin/env bash
# Prints GitHub's generated release notes for <tag> (What's Changed, New
# Contributors, Full Changelog), compared against <previous-tag>, without
# the PRs that already shipped in <previous-tag>.
#
# Usage: release-notes.sh <tag> <target-commit> [previous-tag]
#
# GitHub's generator lists every PR in previous...tag. When the previous
# release was cut from a maintenance branch, that includes the master PRs
# whose fixes were cherry-picked into it, so those are removed here, using
# the same rules as changelog-commits.sh. Only lines ending in a PR link can
# be removed; anything else is left alone.
#
# Requires GH_TOKEN and GITHUB_REPOSITORY in the environment.
set -euo pipefail

tag=${1:?usage: $0 <tag> <target-commit> [previous-tag]}
target=${2:?usage: $0 <tag> <target-commit> [previous-tag]}
previous=${3:-}

args=(-f "tag_name=$tag" -f "target_commitish=$(git rev-parse --verify "$target^{commit}")")
if [ -n "$previous" ]; then
	args+=(-f "previous_tag_name=$previous")
fi
notes=$(gh api -X POST "repos/${GITHUB_REPOSITORY}/releases/generate-notes" "${args[@]}" --jq .body)

if [ -z "$previous" ]; then
	printf '%s\n' "$notes"
	exit 0
fi

scripts=$(dirname "$0")
kept=$("$scripts/changelog-commits.sh" "$previous" "$target")
skipped_prs=$(git rev-list "$previous..$target" | { grep -vxF -f <(printf '%s\n' "$kept") || true; } |
	xargs -r git log --no-walk --format=%s | sed -n 's/.*(#\([0-9][0-9]*\))$/\1/p' | sort -u)

if [ -z "$skipped_prs" ]; then
	printf '%s\n' "$notes"
	exit 0
fi

pattern="/pull/($(paste -sd '|' <<< "$skipped_prs"))\$"
printf '%s\n' "$notes" | tr -d '\r' | grep -vE -- "$pattern"
