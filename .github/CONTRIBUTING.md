Contributing to Caddy
=====================

Welcome! Thank you for choosing to be a part of our community. Caddy wouldn't be great without your involvement!

For starters, we invite you to join [the Caddy forum](https://caddy.community) where you can hang out with other Caddy users and developers.

## Common Tasks

- [Contributing code](#contributing-code)
- [Writing a plugin](#writing-a-plugin)
- [Asking or answering questions for help using Caddy](#getting-help-using-caddy)
- [Reporting a bug](#reporting-bugs)
- [Suggesting an enhancement or a new feature](#suggesting-features)
- [Improving documentation](#improving-documentation)

Other menu items:

- [Values](#values)
- [Responsible Disclosure](#responsible-disclosure)
- [Thank You](#thank-you)


### Contributing code

You can have a direct impact on the project by helping with its code. To contribute code to Caddy, open a [pull request](https://github.com/mholt/caddy/pulls) (PR). If you're new to our community, that's okay: **we gladly welcome pull requests from anyone, regardless of your native language or coding experience.** You can get familiar with Caddy's code base by using [code search at Sourcegraph](https://sourcegraph.com/github.com/mholt/caddy/-/search).

We hold contributions to a high standard for quality :bowtie:, so don't be surprised if we ask for revisions&mdash;even if it seems small or insignificant. Please don't take it personally. :wink: If your change is on the right track, we can guide you to make it mergable.

Here are some of the expectations we have of contributors:

- If your change is more than just a minor alteration, **open an issue to propose your change first.** This way we can avoid confusion, coordinate what everyone is working on, and ensure that changes are in-line with the project's goals and the best interests of its users. If there's already an issue about it, comment on the existing issue to claim it.

- **Keep pull requests small.** Smaller PRs are more likely to be merged because they are easier to review! We might ask you to break up large PRs into smaller ones. [An example of what we DON'T do.](https://twitter.com/iamdevloper/status/397664295875805184)

- **Keep related commits together in a PR.** We do want pull requests to be small, but you should also keep multiple related commits in the same PR if they rely on each other.

- **Write tests.** Tests are essential! Written properly, they ensure your change works, and that other changes in the future won't break your change. CI checks should pass.

- **Benchmarks should be included for optimizations.** Optimizations sometimes make code harder to read or have changes that are less than obvious. They should be proven with benchmarks or profiling.

- **[Squash](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html) insignificant commits.** Every commit should be significant. Commits which merely rewrite a comment or fix a typo can be combined into another commit that has more substance. Interactive rebase can do this, or a simpler way is `git reset --soft <diverging-commit>` then `git commit -s`.

- **Own your contributions.** Caddy is a growing project, and it's much better when individual contributors help maintain their change after it is merged.

- **Use comments properly.** We expect good godoc comments for package-level functions, types, and values. Comments are also useful whenever the purpose for a line of code is not obvious.

We often grant [collaborator status](#collaborator-instructions) to contributors who author one or more significant, high-quality PRs that are merged into the code base!


#### HOW TO MAKE A PULL REQUEST TO CADDY

Contributing to Go projects on GitHub is fun and easy. We recommend the following workflow:

1. [Fork this repo](https://github.com/mholt/caddy). This makes a copy of the code you can write to.

2. If you don't already have this repo (mholt/caddy.git) repo on your computer, get it with `go get github.com/mholt/caddy/caddy`.

3. Tell git that it can push the mholt/caddy.git repo to your fork by adding a remote: `git remote add myfork https://github.com/you/caddy.git`

4. Make your changes in the mholt/caddy.git repo on your computer.

5. Push your changes to your fork: `git push myfork`

6. [Create a pull request](https://github.com/mholt/caddy/pull/new/master) to merge your changes into mholt/caddy @ master. (Click "compare across forks" and change the head fork.)

This workflow is nice because you don't have to change import paths. You can get fancier by using different branches if you want.


### Writing a plugin

Caddy can do more with plugins! Anyone can write a plugin. Plugins are Go libraries that get compiled into Caddy, extending its feature set. They can add directives to the Caddyfile, change how the Caddyfile is loaded, and even implement new server types (e.g. HTTP, DNS). When it's ready, you can submit your plugin to the Caddy website so others can download it.

[Learn how to write and submit a plugin](https://github.com/mholt/caddy/wiki) on the wiki. You should also share and discuss your plugin idea [on the forums](https://caddy.community) to have people test it out. We don't use the Caddy issue tracker for plugins.


### Getting help using Caddy

If you have a question about using Caddy, [ask on our forum](https://caddy.community)! There will be more people there who can help you than just the Caddy developers who follow our issue tracker. Issues are not the place for usage questions.

Many people on the forums could benefit from your experience and expertise, too. Once you've been helped, consider giving back by answering other people's questions and participating in other discussions.


### Reporting bugs

Like every software, Caddy has its flaws. If you find one, [search the issues](https://github.com/mholt/caddy/issues) to see if it has already been reported. If not, [open a new issue](https://github.com/mholt/caddy/issues/new) and describe the bug, and somebody will look into it! (This repository is only for Caddy, not plugins.)

**You can help stop bugs in their tracks!** Speed up the patch by identifying the bug in the code. This can sometimes be done by adding `fmt.Println()` statements (or similar) in relevant code paths to narrow down where the problem may be. It's a good way to [introduce yourself to the Go language](https://tour.golang.org), too.

Please follow the issue template so we have all the needed information. Unredacted&mdash;yes, actual values matter. We need to be able to repeat the bug using your instructions. Please simplify the issue as much as possible. The burden is on you to convince us that it is actually a bug in Caddy. This is easiest to do when you write clear, concise instructions so we can reproduce the behavior (even if it seems obvious). The more detailed and specific you are, the faster we will be able to help you!

We suggest reading [How to Report Bugs Effectively](http://www.chiark.greenend.org.uk/~sgtatham/bugs.html).

Please be kind. :smile: Remember that Caddy comes at no cost to you, and you're getting free support when we fix your issues. If we helped you, please consider helping someone else!


### Suggesting features

First, [search to see if your feature has already been requested](https://github.com/mholt/caddy/issues). If it has, you can add a :+1: reaction to vote for it. If your feature idea is new, open an issue to request the feature. You don't have to follow the bug template for feature requests. Please describe your idea thoroughly so that we know how to implement it! Really vague requests may not be helpful or actionable and without clarification will have to be closed.

While we really do value your requests and implement many of them, not all features are a good fit for Caddy. Most of those [make good plugins](https://github.com/mholt/caddy/wiki), though, which can be made by anyone! But if a feature is not in the best interest of the Caddy project or its users in general, we may politely decline to implement it into Caddy core.


### Improving documentation

Caddy's documentation is available at [https://caddyserver.com/docs](https://caddyserver.com/docs). If you would like to make a fix to the docs, please submit an issue here describing the change to make.

Note that plugin documentation is not hosted by the Caddy website, other than basic usage examples. They are managed by the individual plugin authors, and you will have to contact them to change their documentation.



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

- **Don't accept new dependencies lightly.** Dependencies can make the world crash and burn, but they are sometimes necessary. Choose carefully. Extremely small dependencies (a few lines of code) can be inlined. The rest may not be needed. For those that are, Caddy vendors all dependencies with the help of [gvt](https://github.com/FiloSottile/gvt). All external dependencies must be vendored, and _Caddy must not export any types defined by those dependencies_. Check this diligently!

- **Be extra careful in some areas of the code.** There are some critical areas in the Caddy code base that we review extra meticulously: the `caddy` and `caddytls` packages especially.

- **Make sure tests test the actual thing.** Double-check that the tests fail without the change, and pass with it. It's important that they assert what they're purported to assert.

- **Recommended reading**
	- [CodeReviewComments](https://github.com/golang/go/wiki/CodeReviewComments) for an idea of what we look for in good, clean Go code
	- [Linus Torvalds describes a good commit message](https://gist.github.com/matthewhudson/1475276)
	- [Best Practices for Maintainers](https://opensource.guide/best-practices/)
	- [Shrinking Code Review](https://alexgaynor.net/2015/dec/29/shrinking-code-review/)



## Values

- A person is always more important than code. People don't like being handled "efficiently". But we can still process issues and pull requests efficiently while being kind, patient, and considerate.

- The ends justify the means, if the means are good. A good tree won't produce bad fruit. But if we cut corners or are hasty in our process, the end result will not be good.


## Responsible Disclosure

If you've found a security vulnerability, please email me, the author, directly: Matthew dot Holt at Gmail. I'll need enough information to verify the bug and make a patch. It will speed things up if you suggest a working patch. If your report is valid and a patch is released, we will not reveal your identity by default. If you wish to be credited, please give me the name to use. Thanks for responsibly helping Caddy&mdash;and thousands of websites&mdash;be more secure!


## Thank you

Thanks for your help! Caddy would not be what it is today without your
contributions.
