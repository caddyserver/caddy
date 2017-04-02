<a href="https://caddyserver.com"><img src="https://caddyserver.com/resources/images/caddy-lower.png" alt="Caddy" width="350"></a>

[![community](https://img.shields.io/badge/community-forum-ff69b4.svg?style=flat-square)](https://forum.caddyserver.com) [![twitter](https://img.shields.io/badge/twitter-@caddyserver-55acee.svg?style=flat-square)](https://twitter.com/caddyserver) [![Documentation](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/mholt/caddy) [![Linux Build Status](https://img.shields.io/travis/mholt/caddy.svg?style=flat-square&label=linux+build)](https://travis-ci.org/mholt/caddy) [![Windows Build Status](https://img.shields.io/appveyor/ci/mholt/caddy.svg?style=flat-square&label=windows+build)](https://ci.appveyor.com/project/mholt/caddy)
[![Go Report Card](https://goreportcard.com/badge/github.com/mholt/caddy?style=flat-square)](https://goreportcard.com/report/mholt/caddy)
[![Sourcegraph Badge](https://sourcegraph.com/github.com/mholt/caddy/-/badge.svg)](https://sourcegraph.com/github.com/mholt/caddy?badge)


Caddy is a general-purpose web server for Windows, Mac, Linux, BSD, and
[Android](https://github.com/mholt/caddy/wiki/Running-Caddy-on-Android). It is
a capable but easier alternative to other popular web servers.

[Releases](https://github.com/mholt/caddy/releases) ·
[User Guide](https://caddyserver.com/docs) ·
[Community](https://forum.caddyserver.com)

**Attend the [Caddy launch event](https://www.facebook.com/events/1413078512092363/) on April 20! It's free, and we will try to get a live stream going.**

<a href="https://www.facebook.com/events/1413078512092363/"><img src="http://i.imgur.com/CjGICWU.png" alt="Caddy launch event" width="500"></a>

Try browsing [the code on Sourcegraph](https://sourcegraph.com/github.com/mholt/caddy)!

## Menu

- [Features](#features)
- [Quick Start](#quick-start)
- [Running from Source](#running-from-source)
- [Running in Production](#running-in-production)
- [Contributing](#contributing)
- [About the Project](#about-the-project)



## Features

- **Easy configuration** with Caddyfile
- **Automatic HTTPS** via [Let's Encrypt](https://letsencrypt.org); Caddy
obtains and manages all cryptographic assets for you
- **HTTP/2** enabled by default (powered by Go standard library)
- **Virtual hosting** for hundreds of sites per server instance, including TLS
SNI
- Experimental **QUIC support** for those that like speed
- TLS session ticket **key rotation** for more secure connections
- **Brilliant extensibility** so Caddy can be customized for your needs
- **Runs anywhere** with **no external dependencies** (not even libc)



## Quick Start

Caddy binaries have no dependencies and are available for every platform.
Install Caddy any one of these ways:

- **[Download page](https://caddyserver.com/download)** allows you to
customize your build in the browser
- **[Latest release](https://github.com/mholt/caddy/releases/latest)** for
pre-built binaries
- **curl [getcaddy.com](https://getcaddy.com)** for auto install:
`curl https://getcaddy.com | bash`

Once `caddy` is in your PATH, you can `cd` to your website's folder and run
`caddy` to serve it. By default, Caddy serves the current directory at
[localhost:2015](http://localhost:2015).

To customize how your site is served, create a file named Caddyfile by your
site and paste this into it:

```plain
localhost

gzip
browse
websocket /echo cat
ext    .html
log    /var/log/access.log
proxy  /api 127.0.0.1:7005
header /api Access-Control-Allow-Origin *
```

When you run `caddy` in that directory, it will automatically find and use
that Caddyfile to configure itself.

This simple file enables compression, allows directory browsing (for folders
without an index file), hosts a WebSocket echo server at /echo, serves clean
URLs, logs requests to access.log, proxies all API requests to a backend on
port 7005, and adds the coveted  `Access-Control-Allow-Origin: *` header for
all responses from the API.

Wow! Caddy can do a lot with just a few lines.

To host multiple sites and do more with the Caddyfile, please see the
[Caddyfile documentation](https://caddyserver.com/docs/caddyfile).

Note that production sites are served over
[HTTPS by default](https://caddyserver.com/docs/automatic-https).

Caddy has a command line interface. Run `caddy -h` to view basic help or see
the [CLI documentation](https://caddyserver.com/docs/cli) for details.

**Running as root:** We advise against this. You can still listen on ports
< 1024 using setcap like so: `sudo setcap cap_net_bind_service=+ep ./caddy`



## Running from Source

Note: You will need **[Go 1.8](https://golang.org/dl/)** or newer.

1. `go get github.com/mholt/caddy/caddy`
2. `cd` into your website's directory
3. Run `caddy` (assuming `$GOPATH/bin` is in your `$PATH`)

Caddy's `main()` is in the caddy subfolder. To recompile Caddy, use
`build.bash` found in that folder.



## Running in Production

The Caddy project does not officially maintain any system-specific
integrations, but your download file includes
[unofficial resources](https://github.com/mholt/caddy/tree/master/dist/init)
contributed by the community that you may find helpful for running Caddy in
production.

How you choose to run Caddy is up to you. Many users are satisfied with
`nohup caddy &`. Others use `screen`. Users who need Caddy to come back up
after reboots either do so in the script that caused the reboot, add a command
to an init script, or configure a service with their OS.



## Contributing

**[Join our community](https://forum.caddyserver.com) where you can chat with
other Caddy users and developers!**

Please see our [contributing guidelines](https://github.com/mholt/caddy/blob/master/CONTRIBUTING.md)
and check out the [developer wiki](https://github.com/mholt/caddy/wiki).

We use GitHub issues and pull requests only for discussing bug reports and
the development of specific changes. We welcome all other topics on the
[forum](https://forum.caddyserver.com)!

If you want to contribute to the documentation, please submit pull requests to [caddyserver/caddyserver.com](https://github.com/caddyserver/caddyserver.com).

Thanks for making Caddy -- and the Web -- better!

Special thanks to
[![DigitalOcean](https://i.imgur.com/sfGr0eY.png)](https://www.digitalocean.com)
for hosting the Caddy project.



## About the Project

Caddy was born out of the need for a "batteries-included" web server that runs
anywhere and doesn't have to take its configuration with it. Caddy took
inspiration from [spark](https://github.com/rif/spark),
[nginx](https://github.com/nginx/nginx), lighttpd,
[Websocketd](https://github.com/joewalnes/websocketd)
and [Vagrant](https://www.vagrantup.com/),
which provides a pleasant mixture of features from each of them.

**The name "Caddy":** The name of the software is "Caddy", not "Caddy Server"
or "CaddyServer". Please call it "Caddy" or, if you wish to clarify, "the
Caddy web server". See [brand guidelines](https://caddyserver.com/brand).

*Author on Twitter: [@mholt6](https://twitter.com/mholt6)*
