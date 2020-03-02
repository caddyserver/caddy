Caddy 2
=======

This is the development branch for Caddy 2, the web server of the Go community.

**Caddy 2 is production-ready, but there may be breaking changes before the stable 2.0 release.** Please test it and deploy it as much as you are able, and submit your feedback!

---

<p align="center">
	<a href="https://caddyserver.com"><img src="https://user-images.githubusercontent.com/1128849/36338535-05fb646a-136f-11e8-987b-e6901e717d5a.png" alt="Caddy" width="450"></a>
</p>
<h3 align="center">Every site on HTTPS</h3>
<p align="center">Caddy is an extensible server platform that uses TLS by default.</p>
<p align="center">
	<a href="https://dev.azure.com/mholt-dev/Caddy/_build/latest?definitionId=5&branchName=v2"><img src="https://dev.azure.com/mholt-dev/Caddy/_apis/build/status/Multiplatform%20Tests?branchName=v2"></a>
	<a href="https://pkg.go.dev/github.com/caddyserver/caddy/v2"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
	<a href="https://app.fuzzit.dev/orgs/caddyserver-gh/dashboard"><img src="https://app.fuzzit.dev/badge?org_id=caddyserver-gh"></a>
	<br>
	<a href="https://twitter.com/caddyserver" title="@caddyserver on Twitter"><img src="https://img.shields.io/badge/twitter-@caddyserver-55acee.svg" alt="@caddyserver on Twitter"></a>
	<a href="https://caddy.community" title="Caddy Forum"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg" alt="Caddy Forum"></a>
	<a href="https://sourcegraph.com/github.com/caddyserver/caddy?badge" title="Caddy on Sourcegraph"><img src="https://sourcegraph.com/github.com/caddyserver/caddy/-/badge.svg" alt="Caddy on Sourcegraph"></a>
</p>
<p align="center">
	<a href="https://github.com/caddyserver/caddy/releases">Download</a> ·
	<a href="https://caddyserver.com/docs/">Documentation</a> ·
	<a href="https://caddy.community">Community</a>
</p>



### Menu

- [Build from source](#build-from-source)
	- [With the build script](#with-the-build-script)
	- [Custom with plugins](#custom-with-plugins)
- [Getting started](#getting-started)
- [Overview](#overview)
- [Full documentation](#full-documentation)
- [Getting help](#getting-help)
- [About](#about)

<p align="center">
	<b>Powered by</b>
	<br>
	<a href="https://github.com/caddyserver/certmagic"><img src="https://user-images.githubusercontent.com/1128849/49704830-49d37200-fbd5-11e8-8385-767e0cd033c3.png" alt="CertMagic" width="250"></a>
</p>

## Build from source

Requirements:

- [Go 1.14 or newer](https://golang.org/dl/)
- Do NOT disable [Go modules](https://github.com/golang/go/wiki/Modules) (`export GO111MODULE=on`)

### With the build script

The Caddy source comes with a build script that will embed the proper version information into the Caddy binary.

**Download the `v2` source code:**

```bash
$ git clone -b v2 "https://github.com/caddyserver/caddy.git"
```

**Build:**

```bash
$ caddy/build.sh [<destination>] [<version>]
```

- `<destination>` is the optional destination path for the `caddy` binary (including the filename).
	If not given, it will default to a file named `caddy` in the current directory.
- `<version>` is the Caddy version (Git tag or commit SHA) you want to build.
	If not given, the build script will try to autodetect the version from the Git repository. Otherwise it will build a `(devel)` build without embedded version information.

**Example:**

```bash
$ caddy/build.sh /usr/local/bin/caddy
```

### Custom with plugins

1. Create a new folder: `mkdir caddy`
2. Change into it: `cd caddy`
3. Copy [Caddy's main.go](https://github.com/caddyserver/caddy/blob/v2/cmd/caddy/main.go) into the empty folder. Add imports for any custom plugins you want to add.
4. Initialize a Go module: `go mod init caddy`
5. Pin Caddy version: `go get github.com/caddyserver/caddy/v2@TAG` replacing `TAG` with a git tag or commit.
6. Compile: `go build`




## Quick start

The [Caddy website](https://caddyserver.com/docs/) has documentation that includes tutorials, quick-start guides, reference, and more.

**We recommend that all users do our [Getting Started](https://caddyserver.com/docs/getting-started) guide to become familiar with using Caddy.**

If you've only got a minute, [the website has several quick-start tutorials](https://caddyserver.com/docs/quick-starts) to choose from! However, after finishing a quick-start tutorial, please read more documentation to understand how the software works. 🙂




## Overview

Caddy is most often used as an HTTPS server, but it is suitable for any long-running Go program. First and foremost, it is a platform to run Go applications. Caddy "apps" are just Go programs that are implemented as Caddy modules. Two apps -- `tls` and `http` -- ship standard with Caddy.

Caddy apps instantly benefit from [automated documentation](https://caddyserver.com/docs/json/), graceful on-line [config changes via API](https://caddyserver.com/docs/api), and unification with other Caddy apps.

Although [JSON](https://caddyserver.com/docs/json/) is Caddy's native config language, Caddy can accept input from [config adapters](https://caddyserver.com/docs/config-adapters) which can essentially convert any config format of your choice into JSON: Caddyfile, JSON 5, YAML, TOML, NGINX config, and more.

The primary way to configure Caddy is through [its API](https://caddyserver.com/docs/api), but if you prefer config files, the [command-line interface](https://caddyserver.com/docs/command-line) supports those too.

Caddy exposes an unprecedented level of control compared to any web server in existence. In Caddy, you are usually setting the actual values of the initialized types in memory that power everything from your HTTP handlers and TLS handshakes to your storage medium. Caddy is also ridiculously extensible, with a powerful plugin system that makes vast improvements over other web servers.

To wield the power of this design, you need to know how the config document is structured. Please see the [our documentation site](https://caddyserver.com/docs/) for details about [Caddy's config structure](https://caddyserver.com/docs/json/).

Nearly all of Caddy's configuration is contained in a single config document, rather than being scattered across CLI flags and env variables and a configuration file as with other web servers. This makes managing your server config more straightforward and reduces hidden variables/factors.


## Full documentation

Our website has complete documentation:

**https://caddyserver.com/docs/**

The docs are also open source. You can contribute to them here: https://github.com/caddyserver/website



## Getting help

- We **strongly recommend** that all professionals or companies using Caddy get a support contract through [Ardan Labs](https://www.ardanlabs.com/my/contact-us?dd=caddy) before help is needed.

- Individuals can exchange help for free on our community forum at https://caddy.community. Remember that people give help out of their spare time and good will. The best way to get help is to give it first!

Please use our [issue tracker](/caddyserver/caddy/issues) only for bug reports and feature requests, i.e. actionable development items (support questions will usually be referred to the forums).



## About

**The name "Caddy" is trademarked.** The name of the software is "Caddy", not "Caddy Server" or "CaddyServer". Please call it "Caddy" or, if you wish to clarify, "the Caddy web server". Caddy is a registered trademark of Light Code Labs, LLC.

- _Project on Twitter: [@caddyserver](https://twitter.com/caddyserver)_
- _Author on Twitter: [@mholt6](https://twitter.com/mholt6)_
