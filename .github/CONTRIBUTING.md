Contributing to Caddy
=====================

Welcome! Thank you for choosing to be a part of our community. Caddy wouldn't be nearly as excellent without your involvement!

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

You can have a huge impact on the project by helping with its code. To contribute code to Caddy, first submit or comment in an issue to discuss your contribution, then open a [pull request](https://github.com/caddyserver/caddy/pulls) (PR). If you're new to our community, that's okay: **we gladly welcome pull requests from anyone, regardless of your native language or coding experience.** You can get familiar with Caddy's code base by using [code search at Sourcegraph](https://sourcegraph.com/github.com/caddyserver/caddy).

We hold contributions to a high standard for quality :bowtie:, so don't be surprised if we ask for revisions&mdash;even if it seems small or insignificant. Please don't take it personally. :blue_heart: If your change is on the right track, we can guide you to make it mergeable.

Here are some of the expectations we have of contributors:

- **Open an issue to propose your change first.** This way we can avoid confusion, coordinate what everyone is working on, and ensure that any changes are in-line with the project's goals and the best interests of its users. We can also discuss the best possible implementation. If there's already an issue about it, comment on the existing issue to claim it. A lot of valuable time can be saved by discussing a proposal first.

- **Keep pull requests small.** Smaller PRs are more likely to be merged because they are easier to review! We might ask you to break up large PRs into smaller ones. [An example of what we want to avoid.](https://twitter.com/iamdevloper/status/397664295875805184)

- **Keep related commits together in a PR.** We do want pull requests to be small, but you should also keep multiple related commits in the same PR if they rely on each other.

- **Write tests.** Good, automated tests are very valuable! Written properly, they ensure your change works, and that other changes in the future won't break your change. CI checks should pass.

- **Benchmarks should be included for optimizations.** Optimizations sometimes make code harder to read or have changes that are less than obvious. They should be proven with benchmarks and profiling.

- **[Squash](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html) insignificant commits.** Every commit should be significant. Commits which merely rewrite a comment or fix a typo can be combined into another commit that has more substance. Interactive rebase can do this, or a simpler way is `git reset --soft <diverging-commit>` then `git commit -s`.

- **Be responsible for and maintain your contributions.** Caddy is a growing project, and it's much better when individual contributors help maintain their change after it is merged.

- **Use comments properly.** We expect good godoc comments for package-level functions, types, and values. Comments are also useful whenever the purpose for a line of code is not obvious.

- **Pull requests may still get closed.** The longer a PR stays open and idle, the more likely it is to be closed. If we haven't reviewed it in a while, it probably means the change is not a priority. Please don't take this personally, we're trying to balance a lot of tasks! If nobody else has commented or reacted to the PR, it likely means your change is useful only to you. The reality is this happens quite a lot. We don't tend to accept PRs that aren't generally helpful. For these reasons or others, the PR may get closed even after a review. We are not obligated to accept all proposed changes, even if the best justification we can give is something vague like, "It doesn't sit right." Sometimes PRs are just the wrong thing or the wrong time. Because it is open source, you can always build your own modified version of Caddy with a change you need, even if we reject it in the official repo. Plus, because Caddy is extensible, it's possible your feature could make a great plugin instead!

- **You certify that you wrote and comprehend the code you submit.** The Caddy project welcomes original contributions that comply with [our CLA](https://cla-assistant.io/caddyserver/caddy), meaning that authors must be able to certify that they created or have rights to the code they are contributing. In addition, we require that code is not simply copy-pasted from Q/A sites or AI language models without full comprehension and rigorous testing. In other words: contributors are allowed to refer to communities for assistance and use AI tools such as language models for inspiration, but code which originates from or is assisted by these resources MUST be:

	- Licensed for you to freely share
	- Fully comprehended by you (be able to explain every line of code)
	- Verified by automated tests when feasible, or thorough manual tests otherwise

	We have found that current language models (LLMs, like ChatGPT) may understand code syntax and even problem spaces to an extent, but often fail in subtle ways to convey true knowledge and produce correct algorithms. Integrated tools such as GitHub Copilot and Sourcegraph Cody may be used for inspiration, but code generated by these tools still needs to meet our criteria for licensing, human comprehension, and testing. These tools may be used to help write code comments and tests as long as you can certify they are accurate and correct. Note that it is often more trouble than it's worth to certify that Copilot (for example) is not giving you code that is possibly plagiarised, unlicensed, or licensed with incompatible terms -- as the Caddy project cannot accept such contributions. If that's too difficult for you (or impossible), then we recommend using these resources only for inspiration and write your own code. Ultimately, you (the contributor) are responsible for the code you're submitting.

	As a courtesy to reviewers, we kindly ask that you disclose when contributing code that was generated by an AI tool or copied from another website so we can be aware of what to look for in code review.

We often grant [collaborator status](#collaborator-instructions) to contributors who author one or more significant, high-quality PRs that are merged into the code base.


#### HOW TO MAKE A PULL REQUEST TO CADDY

Contributing to Go projects on GitHub is fun and easy. After you have proposed your change in an issue, we recommend the following workflow:

1. [Fork this repo](https://github.com/caddyserver/caddy). This makes a copy of the code you can write to.

2. If you don't already have this repo (caddyserver/caddy.git) repo on your computer, clone it down: `git clone https://github.com/caddyserver/caddy.git`

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

**You can help us fix bugs!** Speed up the patch by identifying the bug in the code. This can sometimes be done by adding `fmt.Println()` statements (or similar) in relevant code paths to narrow down where the problem may be. It's a good way to [introduce yourself to the Go language](https://tour.golang.org), too.

We may reply with an issue template. Please follow the template so we have all the needed information. Unredacted&mdash;yes, actual values matter. We need to be able to repeat the bug using your instructions. Please simplify the issue as much as possible. If you don't, we might close your report. The burden is on you to make it easily reproducible and to convince us that it is actually a bug in Caddy. This is easiest to do when you write clear, concise instructions so we can reproduce the behavior (even if it seems obvious). The more detailed and specific you are, the faster we will be able to help you!

We suggest reading [How to Report Bugs Effectively](http://www.chiark.greenend.org.uk/~sgtatham/bugs.html).

Please be kind. :smile: Remember that Caddy comes at no cost to you, and you're getting free support when we fix your issues. If we helped you, please consider helping someone else!

#### Bug reporting expectations

Maintainers---or more generally, developers---need three things to act on bugs:

1. To agree or be convinced that it's a bug (reporter's responsibility).
	- A bug is unintentional, undesired, or surprising behavior which violates documentation or relevant spec. It might be either a mistake in the documentation or a bug in the code.
	- This project usually does not work around bugs in other software, systems, and dependencies; instead, we recommend that those bugs are fixed at their source. This sometimes means we close issues or reject PRs that attempt to fix, workaround, or hide bugs in other projects.

2. To be able to understand what is happening (mostly reporter's responsibility).
	- If the reporter can provide satisfactory instructions such that a developer can reproduce the bug, the developer will likely be able to understand the bug, write a test case, and implement a fix. This is the least amount of work for everyone and path to the fastest resolution.
	- Otherwise, the burden is on the reporter to test possible solutions. This is less preferable because it loosens the feedback loop, slows down debugging efforts, obscures the true nature of the problem from the developers, and is unlikely to result in new test cases.

3. A solution, or ideas toward a solution (mostly maintainer's responsibility).
	- Sometimes the best solution is a documentation change.
	- Usually the developers have the best domain knowledge for inventing a solution, but reporters may have ideas or preferences for how they would like the software to work.
	- Security, correctness, and project goals/vision all take priority over a user's preferences.
	- It's simply good business to yield a solution that satisfies the users, and it's even better business to leave them impressed.

Thus, at the very least, the reporter is expected to:

1. Convince the reader that it's a bug in Caddy (if it's not obvious).
2. Reduce the problem down to the minimum specific steps required to reproduce it.

The maintainer is usually able to do the rest; but of course the reporter may invest additional effort to speed up the process.



### Suggesting features

First, [search to see if your feature has already been requested](https://github.com/caddyserver/caddy/issues). If it has, you can add a :+1: reaction to vote for it. If your feature idea is new, open an issue to request the feature. Please describe your idea thoroughly so that we know how to implement it! Really vague requests may not be helpful or actionable and, without clarification, will have to be closed.

While we really do value your requests and implement many of them, not all features are a good fit for Caddy. Most of those [make good modules](#writing-a-caddy-module), which can be made by anyone! But if a feature is not in the best interest of the Caddy project or its users in general, we may politely decline to implement it into Caddy core. Additionally, some features are bad ideas altogether (for either obvious or non-obvious reasons) which may be rejected. We'll try to explain why we reject a feature, but sometimes the best we can do is, "It's not a good fit for the project."


### Improving documentation

Caddy's documentation is available at [https://caddyserver.com/docs](https://caddyserver.com/docs) and its source is in the [website repo](https://github.com/caddyserver/website). If you would like to make a fix to the docs, please submit an issue there describing the change to make.

Note that third-party module documentation is not hosted by the Caddy website, other than basic usage examples. They are managed by the individual module authors, and you will have to contact them to change their documentation.

Our documentation is scoped to the Caddy project only: it is not for describing how other software or systems work, even if they relate to Caddy or web servers. That kind of content [can be found in our community wiki](https://caddy.community/c/wiki/13), however.

## Collaborator Instructions

Collaborators have push rights to the repository. We grant this permission after one or more successful, high-quality PRs are merged! We thank them for their help. The expectations we have of collaborators are:

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



## Values (WIP)

- A person is always more important than code. People don't like being handled "efficiently". But we can still process issues and pull requests efficiently while being kind, patient, and considerate.

- The ends justify the means, if the means are good. A good tree won't produce bad fruit. But if we cut corners or are hasty in our process, the end result will not be good.


## Security Policy

If you think you've found a security vulnerability, please refer to our [Security Policy](https://github.com/caddyserver/caddy/security/policy) document.


## Thank you

Thanks for your help! Caddy would not be what it is today without your contributions.
