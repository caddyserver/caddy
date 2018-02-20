<p align="center">
	<a href="https://caddyserver.com"><img src="https://user-images.githubusercontent.com/1128849/36338535-05fb646a-136f-11e8-987b-e6901e717d5a.png" alt="Caddy" width="450"></a>
</p>
<h3 align="center">Every Site on HTTPS <!-- Serve Confidently --></h3>
<p align="center">Caddy is a general-purpose HTTP/2 web server that serves HTTPS by default.</p>
<p align="center">
	<a href="https://travis-ci.org/mholt/caddy"><img src="https://img.shields.io/travis/mholt/caddy.svg?label=linux+build"></a>
	<a href="https://ci.appveyor.com/project/mholt/caddy"><img src="https://img.shields.io/appveyor/ci/mholt/caddy.svg?label=windows+build"></a>
	<a href="https://godoc.org/github.com/mholt/caddy"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
	<a href="https://goreportcard.com/report/mholt/caddy"><img src="https://goreportcard.com/badge/github.com/mholt/caddy"></a>
	<br>
	<a href="https://twitter.com/caddyserver" title="@caddyserver on Twitter"><img src="https://img.shields.io/badge/twitter-@caddyserver-55acee.svg" alt="@caddyserver on Twitter"></a>
	<a href="https://caddy.community" title="Caddy Forum"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg" alt="Caddy Forum"></a>
	<a href="https://sourcegraph.com/github.com/mholt/caddy?badge" title="Caddy on Sourcegraph"><img src="https://sourcegraph.com/github.com/mholt/caddy/-/badge.svg" alt="Caddy on Sourcegraph"></a>
</p>
<p align="center">
	<a href="https://caddyserver.com/download">Download</a> ·
	<a href="https://caddyserver.com/docs">Documentation</a> ·
	<a href="https://caddy.community">Community</a>
</p>

---

Caddy is a **production-ready** open-source web server that is fast, easy to use, and makes you more productive.

Available for Windows, Mac, Linux, BSD, Solaris, and [Android](https://github.com/mholt/caddy/wiki/Running-Caddy-on-Android).

## Menu

- [Features](#features)
- [Install](#install)
- [Quick Start](#quick-start)
- [Running in Production](#running-in-production)
- [Contributing](#contributing)
- [Donors](#donors)
- [About the Project](#about-the-project)

## Features

- **Easy configuration** with the Caddyfile
- **Automatic HTTPS** on by default (via [Let's Encrypt](https://letsencrypt.org))
- **HTTP/2** by default
- **Virtual hosting** so multiple sites just work
- Experimental **QUIC support** for cutting-edge transmissions
- TLS session ticket **key rotation** for more secure connections
- **Extensible with plugins** because a convenient web server is a helpful one
- **Runs anywhere** with **no external dependencies** (not even libc)

[See a more complete list of features built into Caddy.](https://caddyserver.com/features) On top of all those, Caddy does even more with plugins: choose which plugins you want at [download](https://caddyserver.com/download).

Altogether, Caddy can do things other web servers simply cannot do. Its features and plugins save you time and mistakes, and will cheer you up. Your Caddy instance takes care of the details for you!


## Install

Caddy binaries have no dependencies and are available for every platform. Get Caddy either of these ways:

- **[Download page](https://caddyserver.com/download)** (RECOMMENDED) allows you to customize your build in the browser
- **[Latest release](https://github.com/mholt/caddy/releases/latest)** for pre-built, vanilla binaries


## Build

To build from source you need **[Git](https://git-scm.com/downloads)** and **[Go](https://golang.org/doc/install)** (1.9 or newer). Follow these instruction for fast building:

- Get the source with `go get github.com/mholt/caddy/caddy` and then run `go get github.com/caddyserver/builds`
- Now `cd $GOPATH/src/github.com/mholt/caddy/caddy` and run `go run build.go`

Then make sure the `caddy` binary is in your PATH.

To build for other platforms, use build.go with the `--goos` and `--goarch` flags.


## Quick Start

To serve static files from the current working directory, run:

```
caddy
```

Caddy's default port is 2015, so open your browser to [http://localhost:2015](http://localhost:2015).

### Go from 0 to HTTPS in 5 seconds

If the `caddy` binary has permission to bind to low ports and your domain name's DNS records point to the machine you're on:

```
caddy -host example.com
```

This command serves static files from the current directory over HTTPS. Certificates are automatically obtained and renewed for you! Caddy is also automatically configuring ports 80 and 443 for you, and redirecting HTTP to HTTPS. Cool, huh?

### Customizing your site

To customize how your site is served, create a file named Caddyfile by your site and paste this into it:

```plain
localhost

push
browse
websocket /echo cat
ext    .html
log    /var/log/access.log
proxy  /api 127.0.0.1:7005
header /api Access-Control-Allow-Origin *
```

When you run `caddy` in that directory, it will automatically find and use that Caddyfile.

This simple file enables server push (via Link headers), allows directory browsing (for folders without an index file), hosts a WebSocket echo server at /echo, serves clean URLs, logs requests to an access log, proxies all API requests to a backend on port 7005, and adds the coveted  `Access-Control-Allow-Origin: *` header for all responses from the API.

Wow! Caddy can do a lot with just a few lines.

### Doing more with Caddy

To host multiple sites and do more with the Caddyfile, please see the [Caddyfile tutorial](https://caddyserver.com/tutorial/caddyfile).

Sites with qualifying hostnames are served over [HTTPS by default](https://caddyserver.com/docs/automatic-https).

Caddy has a nice little command line interface. Run `caddy -h` to view basic help or see the [CLI documentation](https://caddyserver.com/docs/cli) for details.


## Running in Production

Caddy is production-ready if you find it to be a good fit for your site and workflow.

**Running as root:** We advise against this. You can still listen on ports < 1024 on Linux using setcap like so: `sudo setcap cap_net_bind_service=+ep ./caddy`

The Caddy project does not officially maintain any system-specific integrations nor suggest how to administer your own system. But your download file includes [unofficial resources](https://github.com/mholt/caddy/tree/master/dist/init) contributed by the community that you may find helpful for running Caddy in production.

How you choose to run Caddy is up to you. Many users are satisfied with `nohup caddy &`. Others use `screen`. Users who need Caddy to come back up after reboots either do so in the script that caused the reboot, add a command to an init script, or configure a service with their OS.

If you have questions or concerns about Caddy' underlying crypto implementations, consult Go's [crypto packages](https://golang.org/pkg/crypto), starting with their documentation, then issues, then the code itself; as Caddy uses mainly those libraries.


## Contributing

**[Join our forum](https://caddy.community) where you can chat with other Caddy users and developers!** To get familiar with the code base, try [Caddy code search on Sourcegraph](https://sourcegraph.com/github.com/mholt/caddy/-/search)!

Please see our [contributing guidelines](https://github.com/mholt/caddy/blob/master/.github/CONTRIBUTING.md) for instructions. If you want to write a plugin, check out the [developer wiki](https://github.com/mholt/caddy/wiki).

We use GitHub issues and pull requests only for discussing bug reports and the development of specific changes. We welcome all other topics on the [forum](https://caddy.community)!

If you want to contribute to the documentation, please submit pull requests to [caddyserver/website](https://github.com/caddyserver/website).

Thanks for making Caddy -- and the Web -- better!


## Donors

- [DigitalOcean](https://m.do.co/c/6d7bdafccf96) is hosting the Caddy project.
- [DNSimple](https://dnsimple.link/resolving-caddy) provides DNS services for Caddy's sites.
- [DNS Spy](https://dnsspy.io) keeps an eye on Caddy's DNS properties.

We thank them for their services. **If you want to help keep Caddy free, please [become a sponsor](https://caddyserver.com/pricing)!**


## About the Project

Caddy was born out of the need for a "batteries-included" web server that runs anywhere and doesn't have to take its configuration with it. Caddy took inspiration from [spark](https://github.com/rif/spark), [nginx](https://github.com/nginx/nginx), lighttpd,
[Websocketd](https://github.com/joewalnes/websocketd) and [Vagrant](https://www.vagrantup.com/), which provides a pleasant mixture of features from each of them.

**The name "Caddy" is trademarked:** The name of the software is "Caddy", not "Caddy Server" or "CaddyServer". Please call it "Caddy" or, if you wish to clarify, "the Caddy web server". See [brand guidelines](https://caddyserver.com/brand). Caddy is a registered trademark of Light Code Labs, LLC.

*Author on Twitter: [@mholt6](https://twitter.com/mholt6)*
