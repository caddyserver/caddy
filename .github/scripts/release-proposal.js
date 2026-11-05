// Shared release proposal logic for the release workflows, loaded from
// actions/github-script with require(). Keeping it in one place makes the
// approval tracker and the release job agree on what an approved proposal is.
//
// A proposal is a draft PR labelled "release-proposal", titled exactly
// "Release Proposal: <version>", whose head commit message carries a
// "Target-Commit: <full sha>" trailer. The trailer is written by the
// Release Proposal workflow; unlike the PR body, it can't be changed
// without pushing a new commit, which makes earlier approvals stale.
'use strict';

const VERSION_RE = /^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/;
const TARGET_COMMIT_RE = /^Target-Commit: ([0-9a-f]{40})$/m;
const REQUIRED_APPROVALS = 2;

function proposalTitle(version) {
  return `Release Proposal: ${version}`;
}

function validateVersion(version) {
  if (!VERSION_RE.test(version)) {
    throw new Error(`invalid release version ${JSON.stringify(version)}`);
  }
}

// parseMaintainers splits the MAINTAINER_LOGINS secret (comma or semicolon
// separated) into lowercased logins. GitHub logins are case-insensitive.
function parseMaintainers(raw) {
  return (raw || '')
    .split(/[,;]/)
    .map(login => login.trim().toLowerCase())
    .filter(login => login.length > 0);
}

// findOpenProposals returns every open release proposal for the version.
async function findOpenProposals({ github, context, version }) {
  validateVersion(version);
  const prs = await github.paginate(github.rest.pulls.list, {
    owner: context.repo.owner,
    repo: context.repo.repo,
    state: 'open',
    per_page: 100,
  });
  return prs.filter(pr =>
    pr.title === proposalTitle(version) &&
    pr.labels.some(label => label.name === 'release-proposal'));
}

// targetCommit reads the Target-Commit trailer from the proposal's head commit.
async function targetCommit({ github, context, pr }) {
  const { data: commit } = await github.rest.git.getCommit({
    owner: context.repo.owner,
    repo: context.repo.repo,
    commit_sha: pr.head.sha,
  });
  const match = commit.message.match(TARGET_COMMIT_RE);
  if (!match) {
    throw new Error(`proposal #${pr.number} head commit ${pr.head.sha} has no Target-Commit trailer`);
  }
  return match[1];
}

// maintainerApprovals returns the maintainers whose latest review approves
// the proposal's current head commit. Plain comments don't change a
// reviewer's verdict, and approvals of an earlier head commit don't count.
async function maintainerApprovals({ github, context, pr, maintainers }) {
  const reviews = await github.paginate(github.rest.pulls.listReviews, {
    owner: context.repo.owner,
    repo: context.repo.repo,
    pull_number: pr.number,
    per_page: 100,
  });
  const latest = new Map();
  for (const review of reviews) {
    if (!review.user || !['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(review.state)) {
      continue;
    }
    const login = review.user.login.toLowerCase();
    const previous = latest.get(login);
    if (!previous || new Date(review.submitted_at) > new Date(previous.submitted_at)) {
      latest.set(login, review);
    }
  }
  return [...latest.entries()]
    .filter(([login, review]) =>
      maintainers.includes(login) &&
      review.state === 'APPROVED' &&
      review.commit_id === pr.head.sha)
    .map(([, review]) => review.user.login);
}

// checkProposal finds the single open proposal for the version and returns
// it with its target commit and maintainer approvals. It throws if there
// isn't exactly one proposal or the maintainer list is empty, so callers
// fail closed.
async function checkProposal({ github, context, version, maintainerLogins }) {
  const maintainers = parseMaintainers(maintainerLogins);
  if (maintainers.length === 0) {
    throw new Error('MAINTAINER_LOGINS is empty; cannot count approvals');
  }
  const proposals = await findOpenProposals({ github, context, version });
  if (proposals.length !== 1) {
    throw new Error(`expected exactly one open PR titled "${proposalTitle(version)}" with the release-proposal label, found ${proposals.length}`);
  }
  const pr = proposals[0];
  const approvers = await maintainerApprovals({ github, context, pr, maintainers });
  return {
    pr,
    targetCommit: await targetCommit({ github, context, pr }),
    approvers,
    approved: approvers.length >= REQUIRED_APPROVALS,
  };
}

module.exports = {
  REQUIRED_APPROVALS,
  checkProposal,
  findOpenProposals,
  proposalTitle,
  validateVersion,
};
