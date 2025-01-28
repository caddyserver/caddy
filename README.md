<p align="center">
	<a href="https://caddyserver.com">
		<picture>
			<source media="(prefers-color-scheme: dark)" srcset="https://user-images.githubusercontent.com/1128849/210187358-e2c39003-9a5e-4dd5-a783-6deb6483ee72.svg">
			<source media="(prefers-color-scheme: light)" srcset="https://user-images.githubusercontent.com/1128849/210187356-dfb7f1c5-ac2e-43aa-bb23-fc014280ae1f.svg">
			<img src="https://user-images.githubusercontent.com/1128849/210187356-dfb7f1c5-ac2e-43aa-bb23-fc014280ae1f.svg" alt="Caddy" width="550">
		</picture>
	</a>
	<br>
	<h3 align="center">a <a href="https://zerossl.com"><img src="https://user-images.githubusercontent.com/55066419/208327323-2770dc16-ec09-43a0-9035-c5b872c2ad7f.svg" height="28" style="vertical-align: -7.7px" valign="middle"></a> project</h3>
</p>
<hr>
<h3 align="center">Every site on HTTPS</h3>
<p align="center">Caddy is an extensible server platform that uses TLS by default.</p>
<p align="center">
	<a href="https://github.com/caddyserver/caddy/actions/workflows/ci.yml"><img src="https://github.com/caddyserver/caddy/actions/workflows/ci.yml/badge.svg"></a>
	<a href="https://pkg.go.dev/github.com/caddyserver/caddy/v2"><img src="https://img.shields.io/badge/godoc-reference-%23007d9c.svg"></a>
	<br>
	<a href="https://twitter.com/caddyserver" title="@caddyserver on Twitter"><img src="https://img.shields.io/badge/twitter-@caddyserver-55acee.svg" alt="@caddyserver on Twitter"></a>
	<a href="https://caddy.community" title="Caddy Forum"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg" alt="Caddy Forum"></a>
	<br>
	<a href="https://sourcegraph.com/github.com/caddyserver/caddy?badge" title="Caddy on Sourcegraph"><img src="https://sourcegraph.com/github.com/caddyserver/caddy/-/badge.svg" alt="Caddy on Sourcegraph"></a>
	<a href="https://cloudsmith.io/~caddy/repos/"><img src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith" alt="Cloudsmith"></a>
</p>
<p align="center">
	<a href="https://github.com/caddyserver/caddy/releases">Releases</a> ·
	<a href="https://caddyserver.com/docs/">Documentation</a> ·
	<a href="https://caddy.community">Get Help</a>
</p>



### Menu

- [Features](#features)
- [Install](#install)
- [Build from source](#build-from-source)
	- [For development](#for-development)
	- [With version information and/or plugins](#with-version-information-andor-plugins)
- [Quick start](#quick-start)
- [Overview](#overview)
- [Full documentation](#full-documentation)
- [Getting help](#getting-help)
- [About](#about)

<p align="center">
	<b>Powered by</b>
	<br>
	<a href="https://github.com/caddyserver/certmagic">
		<picture>
			<source media="(prefers-color-scheme: dark)" srcset="https://user-images.githubusercontent.com/55066419/206946718-740b6371-3df3-4d72-a822-47e4c48af999.png">
			<source media="(prefers-color-scheme: light)" srcset="https://user-images.githubusercontent.com/1128849/49704830-49d37200-fbd5-11e8-8385-767e0cd033c3.png">
			<img src="https://user-images.githubusercontent.com/1128849/49704830-49d37200-fbd5-11e8-8385-767e0cd033c3.png" alt="CertMagic" width="250">
		</picture>
	</a>
</p>


## [Features](https://caddyserver.com/features)

- **Easy configuration** with the [Caddyfile](https://caddyserver.com/docs/caddyfile)
- **Powerful configuration** with its [native JSON config](https://caddyserver.com/docs/json/)
- **Dynamic configuration** with the [JSON API](https://caddyserver.com/docs/api)
- [**Config adapters**](https://caddyserver.com/docs/config-adapters) if you don't like JSON
- **Automatic HTTPS** by default
	- [ZeroSSL](https://zerossl.com) and [Let's Encrypt](https://letsencrypt.org) for public names
	- Fully-managed local CA for internal names & IPs
	- Can coordinate with other Caddy instances in a cluster
	- Multi-issuer fallback
- **Stays up when other servers go down** due to TLS/OCSP/certificate-related issues
- **Production-ready** after serving trillions of requests and managing millions of TLS certificates
- **Scales to hundreds of thousands of sites** as proven in production
- **HTTP/1.1, HTTP/2, and HTTP/3** all supported by default
- **Highly extensible** [modular architecture](https://caddyserver.com/docs/architecture) lets Caddy do anything without bloat
- **Runs anywhere** with **no external dependencies** (not even libc)
- Written in Go, a language with higher **memory safety guarantees** than other servers
- Actually **fun to use**
- So much more to [discover](https://caddyserver.com/features)

## Install

The simplest, cross-platform way to get started is to download Caddy from [GitHub Releases](https://github.com/caddyserver/caddy/releases) and place the executable file in your PATH.

See [our online documentation](https://caddyserver.com/docs/install) for other install instructions.

## Build from source

Requirements:

- [Go 1.22.3 or newer](https://golang.org/dl/)

### For development

_**Note:** These steps [will not embed proper version information](https://github.com/golang/go/issues/29228). For that, please follow the instructions in the next section._

```bash
$ git clone "https://github.com/caddyserver/caddy.git"
$ cd caddy/cmd/caddy/
$ go build
```

When you run Caddy, it may try to bind to low ports unless otherwise specified in your config. If your OS requires elevated privileges for this, you will need to give your new binary permission to do so. On Linux, this can be done easily with: `sudo setcap cap_net_bind_service=+ep ./caddy`

If you prefer to use `go run` which only creates temporary binaries, you can still do this with the included `setcap.sh` like so:

```bash
$ go run -exec ./setcap.sh main.go
```

If you don't want to type your password for `setcap`, use `sudo visudo` to edit your sudoers file and allow your user account to run that command without a password, for example:

```
username ALL=(ALL:ALL) NOPASSWD: /usr/sbin/setcap
```

replacing `username` with your actual username. Please be careful and only do this if you know what you are doing! We are only qualified to document how to use Caddy, not Go tooling or your computer, and we are providing these instructions for convenience only; please learn how to use your own computer at your own risk and make any needful adjustments.

### With version information and/or plugins

Using [our builder tool, `xcaddy`](https://github.com/caddyserver/xcaddy)...

```
$ xcaddy build
```

...the following steps are automated:

1. Create a new folder: `mkdir caddy`
2. Change into it: `cd caddy`
3. Copy [Caddy's main.go](https://github.com/caddyserver/caddy/blob/master/cmd/caddy/main.go) into the empty folder. Add imports for any custom plugins you want to add.
4. Initialize a Go module: `go mod init caddy`
5. (Optional) Pin Caddy version: `go get github.com/caddyserver/caddy/v2@version` replacing `version` with a git tag, commit, or branch name.
6. (Optional) Add plugins by adding their import: `_ "import/path/here"`
7. Compile: `go build -tags=nobadger,nomysql,nopgx`




## Quick start

The [Caddy website](https://caddyserver.com/docs/) has documentation that includes tutorials, quick-start guides, reference, and more.

**We recommend that all users -- regardless of experience level -- do our [Getting Started](https://caddyserver.com/docs/getting-started) guide to become familiar with using Caddy.**

If you've only got a minute, [the website has several quick-start tutorials](https://caddyserver.com/docs/quick-starts) to choose from! However, after finishing a quick-start tutorial, please read more documentation to understand how the software works. 🙂




## Overview

Caddy is most often used as an HTTPS server, but it is suitable for any long-running Go program. First and foremost, it is a platform to run Go applications. Caddy "apps" are just Go programs that are implemented as Caddy modules. Two apps -- `tls` and `http` -- ship standard with Caddy.

Caddy apps instantly benefit from [automated documentation](https://caddyserver.com/docs/json/), graceful on-line [config changes via API](https://caddyserver.com/docs/api), and unification with other Caddy apps.

Although [JSON](https://caddyserver.com/docs/json/) is Caddy's native config language, Caddy can accept input from [config adapters](https://caddyserver.com/docs/config-adapters) which can essentially convert any config format of your choice into JSON: Caddyfile, JSON 5, YAML, TOML, NGINX config, and more.

The primary way to configure Caddy is through [its API](https://caddyserver.com/docs/api), but if you prefer config files, the [command-line interface](https://caddyserver.com/docs/command-line) supports those too.

Caddy exposes an unprecedented level of control compared to any web server in existence. In Caddy, you are usually setting the actual values of the initialized types in memory that power everything from your HTTP handlers and TLS handshakes to your storage medium. Caddy is also ridiculously extensible, with a powerful plugin system that makes vast improvements over other web servers.

To wield the power of this design, you need to know how the config document is structured. Please see [our documentation site](https://caddyserver.com/docs/) for details about [Caddy's config structure](https://caddyserver.com/docs/json/).

Nearly all of Caddy's configuration is contained in a single config document, rather than being scattered across CLI flags and env variables and a configuration file as with other web servers. This makes managing your server config more straightforward and reduces hidden variables/factors.


## Full documentation

Our website has complete documentation:

**https://caddyserver.com/docs/**

The docs are also open source. You can contribute to them here: https://github.com/caddyserver/website



## Getting help

- We advise companies using Caddy to secure a support contract through [Ardan Labs](https://www.ardanlabs.com) before help is needed.

- A [sponsorship](https://github.com/sponsors/mholt) goes a long way! We can offer private help to sponsors. If Caddy is benefitting your company, please consider a sponsorship. This not only helps fund full-time work to ensure the longevity of the project, it provides your company the resources, support, and discounts you need; along with being a great look for your company to your customers and potential customers!

- Individuals can exchange help for free on our community forum at https://caddy.community. Remember that people give help out of their spare time and good will. The best way to get help is to give it first!

Please use our [issue tracker](https://github.com/caddyserver/caddy/issues) only for bug reports and feature requests, i.e. actionable development items (support questions will usually be referred to the forums).



## About

Matthew Holt began developing Caddy in 2014 while studying computer science at Brigham Young University. (The name "Caddy" was chosen because this software helps with the tedious, mundane tasks of serving the Web, and is also a single place for multiple things to be organized together.) It soon became the first web server to use HTTPS automatically and by default, and now has hundreds of contributors and has served trillions of HTTPS requests.

**The name "Caddy" is trademarked.** The name of the software is "Caddy", not "Caddy Server" or "CaddyServer". Please call it "Caddy" or, if you wish to clarify, "the Caddy web server". Caddy is a registered trademark of Stack Holdings GmbH.

- _Project on Twitter: [@caddyserver](https://twitter.com/caddyserver)_
- _Author on Twitter: [@mholt6](https://twitter.com/mholt6)_

Caddy is a project of [ZeroSSL](https://zerossl.com), a Stack Holdings company.

Debian package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com). Cloudsmith is the only fully hosted, cloud-native, universal package management solution, that enables your organization to create, store and share packages in any format, to any place, with total confidence.
