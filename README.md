[![Caddy](https://caddyserver.com/resources/images/caddy-boxed.png)](https://caddyserver.com)

[![Dev Chat](https://img.shields.io/badge/dev%20chat-gitter-ff69b4.svg?style=flat-square&label=dev+chat&color=ff69b4)](https://gitter.im/mholt/caddy) 
[![Documentation](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/mholt/caddy) 
[![Linux Build Status](https://img.shields.io/travis/mholt/caddy.svg?style=flat-square&label=linux+build)](https://travis-ci.org/mholt/caddy) 
[![Windows Build Status](https://img.shields.io/appveyor/ci/mholt/caddy.svg?style=flat-square&label=windows+build)](https://ci.appveyor.com/project/mholt/caddy)

Caddy is a lightweight, general-purpose web server for Windows, Mac, Linux, BSD 
and [Android](https://github.com/mholt/caddy/wiki/Running-Caddy-on-Android). 
It is a capable alternative to other popular and easy to use web servers. 
([@caddyserver](https://twitter.com/caddyserver) on Twitter)

The most notable features are HTTP/2, [Let's Encrypt](https://letsencrypt.org) 
support, Virtual Hosts, TLS + SNI, and easy configuration with a 
[Caddyfile](https://caddyserver.com/docs/caddyfile). In development, you usually 
put one Caddyfile with each site. In production, Caddy serves HTTPS by default 
and manages all cryptographic assets for you.

[Download](https://github.com/mholt/caddy/releases) · 
[User Guide](https://caddyserver.com/docs)



### Menu

- [Getting Caddy](#getting-caddy)
- [Quick Start](#quick-start)
- [Running from Source](#running-from-source)
- [Contributing](#contributing)
- [About the Project](#about-the-project)




## Getting Caddy

Caddy binaries have no dependencies and are available for nearly every platform.

[Latest release](https://github.com/mholt/caddy/releases/latest)



## Quick Start

The website has [full documentation](https://caddyserver.com/docs) but this will 
get you started in about 30 seconds:

Place a file named "Caddyfile" with your site. Paste this into it and save:

```
localhost

gzip
browse
ext .html
websocket /echo cat
log ../access.log
header /api Access-Control-Allow-Origin *
```

Run `caddy` from that directory, and it will automatically use that Caddyfile to 
configure itself.

That simple file enables compression, allows directory browsing (for folders 
without an index file), serves clean URLs, hosts a WebSocket echo server at 
/echo, logs requests to access.log, and adds the coveted 
`Access-Control-Allow-Origin: *` header for all responses from some API.

Wow! Caddy can do a lot with just a few lines.


#### Defining multiple sites

You can run multiple sites from the same Caddyfile, too:

```
site1.com {
	# ...
}

site2.com, sub.site2.com {
	# ...
}
```

Note that all these sites will automatically be served over HTTPS using Let's 
Encrypt as the CA. Caddy will manage the certificates (including renewals) for 
you. You don't even have to think about it.

For more documentation, please view [the website](https://caddyserver.com/docs). 
You may also be interested in the [developer guide]
(https://github.com/mholt/caddy/wiki) on this project's GitHub wiki.




## Running from Source

Note: You will need **[Go 1.4](https://golang.org/dl/)** or a later version.

1. `$ go get github.com/mholt/caddy`
2. `cd` into your website's directory
3. Run `caddy` (assumes `$GOPATH/bin` is in your `$PATH`)

If you're tinkering, you can also use `go run main.go`.

By default, Caddy serves the current directory at 
[localhost:2015](http://localhost:2015). You can place a Caddyfile to configure 
Caddy for serving your site.

Caddy accepts some flags from the command line. Run `caddy -h` to view the help
 for flags. You can also pipe a Caddyfile into the caddy command.

**Running as root:** We advise against this; use setcap instead, like so: 
`setcap cap_net_bind_service=+ep ./caddy` This will allow you to listen on 
ports < 1024 like 80 and 443.



#### Docker Container

Caddy is available as a Docker container from any of these sources:

- [abiosoft/caddy](https://hub.docker.com/r/abiosoft/caddy/)
- [darron/caddy](https://hub.docker.com/r/darron/caddy/)
- [joshix/caddy](https://hub.docker.com/r/joshix/caddy/)
- [jumanjiman/caddy](https://hub.docker.com/r/jumanjiman/caddy/)
- [zenithar/nano-caddy](https://hub.docker.com/r/zenithar/nano-caddy/)



#### 3rd-party dependencies

Although Caddy's binaries are completely static, Caddy relies on some excellent
libraries. [Godoc.org](https://godoc.org/github.com/mholt/caddy) shows the
packages that each Caddy package imports.




## Contributing

**[Join our dev chat on Gitter](https://gitter.im/mholt/caddy)** to chat with
other Caddy developers! (Dev chat only; try our
[support room](https://gitter.im/caddyserver/support) for help or
[general](https://gitter.im/caddyserver/general) for anything else.)

This project would not be what it is without your help. Please see the
[contributing guidelines](https://github.com/mholt/caddy/blob/master/CONTRIBUTING.md)
if you haven't already.

Thanks for making Caddy -- and the Web -- better!

Special thanks to
[![DigitalOcean](http://i.imgur.com/sfGr0eY.png)](https://www.digitalocean.com)
for hosting the Caddy project.




## About the project

Caddy was born out of the need for a "batteries-included" web server that runs
anywhere and doesn't have to take its configuration with it. Caddy took
inspiration from [spark](https://github.com/rif/spark),
[nginx](https://github.com/nginx/nginx), lighttpd,
[Websocketd](https://github.com/joewalnes/websocketd)
and [Vagrant](https://www.vagrantup.com/),
which provides a pleasant mixture of features from each of them.


*Twitter: [@mholt6](https://twitter.com/mholt6)*
