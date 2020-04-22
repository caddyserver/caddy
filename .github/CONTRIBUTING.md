Contributing to Caddy
=====================

Welcome! Thank you for choosing to be a part of our community. Caddy wouldn't be great without your involvement!

For starters, we invite you to join [the Caddy forum](https://caddy.community) where you can hang out with other Caddy users and developers.

## Common Tasks

- [Contributing code](#contributing-code)
- [Writing a Caddy module](#writing-a-caddy-module)
- [Asking or answering questions for help using Caddy](#getting-help-using-caddy)
- [Reporting a bug](#reporting-bugs)
- [Suggesting an enhancement or a new feature](#suggesting-features)
- [Improving documentation](#improving-documentation)

Other menu items:

- [Values](#values)
- [Coordinated Disclosure](#coordinated-disclosure)
- [Thank You](#thank-you)


### Contributing code

You can have a huge impact on the project by helping with its code. To contribute code to Caddy, open a [pull request](https://github.com/caddyserver/caddy/pulls) (PR). If you're new to our community, that's okay: **we gladly welcome pull requests from anyone, regardless of your native language or coding experience.** You can get familiar with Caddy's code base by using [code search at Sourcegraph](https://sourcegraph.com/github.com/caddyserver/caddy/-/search).

We hold contributions to a high standard for quality :bowtie:, so don't be surprised if we ask for revisions&mdash;even if it seems small or insignificant. Please don't take it personally. :blue_heart: If your change is on the right track, we can guide you to make it mergable.

Here are some of the expectations we have of contributors:

- **Open an issue to propose your change first.** This way we can avoid confusion, coordinate what everyone is working on, and ensure that any changes are in-line with the project's goals and the best interests of its users. We can also discuss the best possible implementation. If there's already an issue about it, comment on the existing issue to claim it.

- **Keep pull requests small.** Smaller PRs are more likely to be merged because they are easier to review! We might ask you to break up large PRs into smaller ones. [An example of what we want to avoid.](https://twitter.com/iamdevloper/status/397664295875805184)

- **Keep related commits together in a PR.** We do want pull requests to be small, but you should also keep multiple related commits in the same PR if they rely on each other.

- **Write tests.** Tests are essential! Written properly, they ensure your change works, and that other changes in the future won't break your change. CI checks should pass.

- **Benchmarks should be included for optimizations.** Optimizations sometimes make code harder to read or have changes that are less than obvious. They should be proven with benchmarks or profiling.

- **[Squash](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html) insignificant commits.** Every commit should be significant. Commits which merely rewrite a comment or fix a typo can be combined into another commit that has more substance. Interactive rebase can do this, or a simpler way is `git reset --soft <diverging-commit>` then `git commit -s`.

- **Own your contributions.** Caddy is a growing project, and it's much better when individual contributors help maintain their change after it is merged.

- **Use comments properly.** We expect good godoc comments for package-level functions, types, and values. Comments are also useful whenever the purpose for a line of code is not obvious.

We often grant [collaborator status](#collaborator-instructions) to contributors who author one or more significant, high-quality PRs that are merged into the code base!


#### HOW TO MAKE A PULL REQUEST TO CADDY

Contributing to Go projects on GitHub is fun and easy. We recommend the following workflow:

1. [Fork this repo](https://github.com/caddyserver/caddy). This makes a copy of the code you can write to.

2. If you don't already have this repo (caddyserver/caddy.git) repo on your computer, get it with `go get github.com/caddyserver/caddy/v2`.

3. Tell git that it can push the caddyserver/caddy.git repo to your fork by adding a remote: `git remote add myfork https://github.com/<your-username>/caddy.git`

4. Make your changes in the caddyserver/caddy.git repo on your computer.

5. Push your changes to your fork: `git push myfork`

6. [Create a pull request](https://github.com/caddyserver/caddy/pull/new/master) to merge your changes into caddyserver/caddy @ master. (Click "compare across forks" and change the head fork.)

This workflow is nice because you don't have to change import paths. You can get fancier by using different branches if you want.


### Writing a Caddy module

Caddy can do more with modules! Anyone can write one. Caddy modules are Go libraries that get compiled into Caddy, extending its feature set. They can add directives to the Caddyfile, add new configuration adapters, and even implement new server types (e.g. HTTP, DNS).

[Learn how to write a module here](https://caddyserver.com/docs/extending-caddy). You should also share and discuss your module idea [on the forums](https://caddy.community) to have people test it out. We don't use the Caddy issue tracker for third-party modules.


### Getting help using Caddy

If you have a question about using Caddy, [ask on our forum](https://caddy.community)! There will be more people there who can help you than just the Caddy developers who follow our issue tracker. Issues are not the place for usage questions.

Many people on the forums could benefit from your experience and expertise, too. Once you've been helped, consider giving back by answering other people's questions and participating in other discussions.


### Reporting bugs

Like every software, Caddy has its flaws. If you find one, [search the issues](https://github.com/caddyserver/caddy/issues) to see if it has already been reported. If not, [open a new issue](https://github.com/caddyserver/caddy/issues/new) and describe the bug, and somebody will look into it! (This repository is only for Caddy and its standard modules.)

**You can help stop bugs in their tracks!** Speed up the patch by identifying the bug in the code. This can sometimes be done by adding `fmt.Println()` statements (or similar) in relevant code paths to narrow down where the problem may be. It's a good way to [introduce yourself to the Go language](https://tour.golang.org), too.

Please follow the issue template so we have all the needed information. Unredacted&mdash;yes, actual values matter. We need to be able to repeat the bug using your instructions. Please simplify the issue as much as possible. The burden is on you to convince us that it is actually a bug in Caddy. This is easiest to do when you write clear, concise instructions so we can reproduce the behavior (even if it seems obvious). The more detailed and specific you are, the faster we will be able to help you!

We suggest reading [How to Report Bugs Effectively](http://www.chiark.greenend.org.uk/~sgtatham/bugs.html).

Please be kind. :smile: Remember that Caddy comes at no cost to you, and you're getting free support when we fix your issues. If we helped you, please consider helping someone else!

#### Bug reporting expectations

Maintainers---or more generally, developers---need three things to act on bugs:

1. To agree or be convinced that it's a bug (reporter's responsibility).
	- A bug is undesired or surprising behavior which violates documentation or the spec.

2. To be able to understand what is happening (mostly reporter's responsibility).
	- If the reporter can provide satisfactory instructions such that a developer can reproduce the bug, the developer will likely be able to understand the bug, write a test case, and implement a fix.
	- Otherwise, the burden is on the reporter to test possible solutions. This is discouraged because it loosens the feedback loop, slows down debugging efforts, obscures the true nature of the problem from the developers, and is unlikely to result in new test cases.

3. A solution, or ideas toward a solution (mostly maintainer's responsibility).
	- Sometimes the best solution is a documentation change.
	- Usually the developers have the best domain knowledge for inventing a solution, but reporters may have ideas or preferences for how they would like the software to work.
	- Security, correctness, and project goals/vision all take priority over a user's preferences.
	- It's simply good business to yield a solution that satisfies the users, and it's even better business to leave them impressed.

Thus, at the very least, the reporter is expected to:

1. Convince the reader that it's a bug (if it's not obvious).
2. Reduce the problem down to the minimum specific steps required to reproduce it.

The maintainer is usually able to do the rest; but of course the reporter may invest additional effort to speed up the process.



### Suggesting features

First, [search to see if your feature has already been requested](https://github.com/caddyserver/caddy/issues). If it has, you can add a :+1: reaction to vote for it. If your feature idea is new, open an issue to request the feature. Please describe your idea thoroughly so that we know how to implement it! Really vague requests may not be helpful or actionable and, without clarification, will have to be closed.

While we really do value your requests and implement many of them, not all features are a good fit for Caddy. Most of those [make good modules](#writing-a-caddy-module), which can be made by anyone! But if a feature is not in the best interest of the Caddy project or its users in general, we may politely decline to implement it into Caddy core.


### Improving documentation

Caddy's documentation is available at [https://caddyserver.com/docs](https://caddyserver.com/docs) and its source is in the [website repo](https://github.com/caddyserver/website). If you would like to make a fix to the docs, please submit an issue there describing the change to make.

Note that third-party module documentation is not hosted by the Caddy website, other than basic usage examples. They are managed by the individual module authors, and you will have to contact them to change their documentation.



## Collaborator Instructions

Collaborators have push rights to the repository. We grant this permission after one or more successful, high-quality PRs are merged! We thank them for their help.The expectations we have of collaborators are:

- **Help review pull requests.** Be meticulous, but also kind. We love our contributors, but we critique the contribution to make it better. Multiple, thorough reviews make for the best contributions! Here are some questions to consider:
	- Can the change be made more elegant?
	- Is this a maintenance burden?
	- What assumptions does the code make?
	- Is it well-tested?
	- Is the change a good fit for the project?
	- Does it actually fix the problem or is it creating a special case instead?
	- Does the change incur any new dependencies? (Avoid these!)

- **Answer issues.** If every collaborator helped out with issues, we could count the number of open issues on two hands. This means getting involved in the discussion, investigating the code, and yes, debugging it. It's fun. Really! :smile: Please, please help with open issues. Granted, some issues need to be done before others. And of course some are larger than others: you don't have to do it all yourself. Work with other collaborators as a team!

- **Do not merge pull requests until they have been approved by one or two other collaborators.** If a project owner approves the PR, it can be merged (as long as the conversation has finished too).

- **Prefer squashed commits over a messy merge.** If there are many little commits, please [squash the commits](https://stackoverflow.com/a/11732910/1048862) so we don't clutter the commit history.

- **Don't accept new dependencies lightly.** Dependencies can make the world crash and burn, but they are sometimes necessary. Choose carefully. Extremely small dependencies (a few lines of code) can be inlined. The rest may not be needed. For those that are, Caddy uses [go modules](https://github.com/golang/go/wiki/Modules). All external dependencies must be installed as modules, and _Caddy must not export any types defined by those dependencies_. Check this diligently!

- **Be extra careful in some areas of the code.** There are some critical areas in the Caddy code base that we review extra meticulously: the `caddyhttp` and `caddytls` packages especially.

- **Make sure tests test the actual thing.** Double-check that the tests fail without the change, and pass with it. It's important that they assert what they're purported to assert.

- **Recommended reading**
	- [CodeReviewComments](https://github.com/golang/go/wiki/CodeReviewComments) for an idea of what we look for in good, clean Go code
	- [Linus Torvalds describes a good commit message](https://gist.github.com/matthewhudson/1475276)
	- [Best Practices for Maintainers](https://opensource.guide/best-practices/)
	- [Shrinking Code Review](https://alexgaynor.net/2015/dec/29/shrinking-code-review/)



## Values

- A person is always more important than code. People don't like being handled "efficiently". But we can still process issues and pull requests efficiently while being kind, patient, and considerate.

- The ends justify the means, if the means are good. A good tree won't produce bad fruit. But if we cut corners or are hasty in our process, the end result will not be good.


## Security Policy

If you think you've found a security vulnerability, please refer to our [Security Policy](https://github.com/caddyserver/caddy/security/policy) document.


## Thank you

Thanks for your help! Caddy would not be what it is today without your contributions.
