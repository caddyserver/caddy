#!/usr/bin/env bash
# Prints the commits that are new in <target> compared to the release <base>,
# oldest first, one SHA per line.
#
# Usage: changelog-commits.sh <base> <target>
#
# When <base> is an ancestor of <target>, that's simply base..target. When it
# isn't (e.g. base is a 2.11.x release cut from a maintenance branch and
# target is on master), base..target also contains the master commits whose
# fixes were already cherry-picked into the base release. Those are skipped
# when any of the following holds:
#
#   1. The commit has the same patch ID as a commit on the base side
#      (a clean cherry-pick).
#   2. Cherry-picking it onto the base would change nothing, but
#      cherry-picking it onto the merge base would. That is, the base
#      already has the change, and it got there after the branches split.
#      This catches clean picks whose lines were changed again later. The
#      merge-base condition keeps a revert of something the base never had
#      (which would also change nothing) in the list.
#   3. Its subject ends with a PR number, e.g. "(#1234)", and a commit on
#      the base side has the identical subject. This catches backports that
#      had to be adapted to apply. Subjects without a PR number are never
#      matched this way: unrelated commits can share one (for example
#      GitHub's "Merge commit from fork" for security advisories).
set -euo pipefail

base=$(git rev-parse --verify "${1:?usage: $0 <base> <target>}^{commit}")
target=$(git rev-parse --verify "${2:?usage: $0 <base> <target>}^{commit}")

if git merge-base --is-ancestor "$base" "$target"; then
	git rev-list --reverse "$base..$target"
	exit 0
fi

merge_base=$(git merge-base "$base" "$target")
base_tree=$(git rev-parse "$base^{tree}")
merge_base_tree=$(git rev-parse "$merge_base^{tree}")
backported_subjects=$(git log --format=%s "$merge_base..$base" | grep -E '\(#[0-9]+\)$' || true)

# picking_changes_nothing <commit> <onto> <onto-tree>
picking_changes_nothing() {
	local result
	if ! result=$(git merge-tree --write-tree --merge-base="$1^" "$2" "$1" 2>/dev/null); then
		return 1 # conflicts, so it would change something
	fi
	[ "$(head -n 1 <<< "$result")" = "$3" ]
}

for commit in $(git rev-list --reverse --cherry-pick --right-only "$base...$target"); do
	subject=$(git log -1 --format=%s "$commit")
	if [[ $subject =~ \(#[0-9]+\)$ ]] && grep -qxF -- "$subject" <<< "$backported_subjects"; then
		continue
	fi
	if picking_changes_nothing "$commit" "$base" "$base_tree" &&
		! picking_changes_nothing "$commit" "$merge_base" "$merge_base_tree"; then
		continue
	fi
	echo "$commit"
done
