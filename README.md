[![Caddy](https://caddyserver.com/resources/images/caddy-boxed.png)](https://caddyserver.com)

[![Documentation](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/mholt/caddy) [![Build Status](https://img.shields.io/travis/mholt/caddy.svg?style=flat-square)](https://travis-ci.org/mholt/caddy)

Caddy is a lightweight, general-purpose web server for Windows, Mac, Linux, BSD, and [Android](https://github.com/mholt/caddy/wiki/Running-Caddy-on-Android). It is a capable alternative to other popular and easy to use web servers.

The most notable features are HTTP/2, Virtual Hosts, TLS + SNI, and easy configuration with a [Caddyfile](https://caddyserver.com/docs/caddyfile). Usually, you have one Caddyfile per site. Most directives for the Caddyfile invoke a layer of middleware which can be [used in your own Go programs](https://github.com/mholt/caddy/wiki/Using-Caddy-Middleware-in-Your-Own-Programs).

[Download](https://github.com/mholt/caddy/releases) · [User Guide](https://caddyserver.com/docs)




### Menu

- [Getting Caddy](#getting-caddy)
- [Running from Source](#running-from-source)
- [Quick Start](#quick-start)
- [Contributing](#contributing)
- [About the Project](#about-the-project)




## Getting Caddy

Caddy binaries have no dependencies and are available for nearly every platform.

[Latest release](https://github.com/mholt/caddy/releases/latest)


## Running from Source

Note: You will need **[Go 1.4](https://golang.org/dl)** or newer

1. `$ go get github.com/mholt/caddy`
2. `cd` into your website's directory
3. Run `caddy` (assumes `$GOPATH/bin` is in your `$PATH`)

If you're tinkering, you can also use `go run main.go`.

By default, Caddy serves the current directory at [localhost:2015](http://localhost:2015). You can place a Caddyfile to configure Caddy for serving your site.

Caddy accepts some flags from the command line. Run `caddy -h` to view the help for flags. You can also pipe a Caddyfile into the caddy command.

**Running as root:** We advise against this; use setcap instead, like so: `setcap cap_net_bind_service=+ep ./caddy` This will allow you to listen on ports below 1024 (like 80 and 443).


#### Docker Container

Caddy is available as a Docker container from any of these sources:

- [abiosoft/caddy](https://registry.hub.docker.com/u/abiosoft/caddy/)
- [darron/caddy](https://registry.hub.docker.com/u/darron/caddy/)
- [joshix/caddy](https://registry.hub.docker.com/u/joshix/caddy/)
- [jumanjiman/caddy](https://registry.hub.docker.com/u/jumanjiman/caddy/)
- [zenithar/nano-caddy](https://registry.hub.docker.com/u/zenithar/nano-caddy/)


#### 3rd-party libraries

Although Caddy's binaries are completely static, Caddy relies on some excellent libraries. [Godoc.org](https://godoc.org/github.com/mholt/caddy) shows the packages that each Caddy package imports.




## Quick Start

The website has [full documentation](https://caddyserver.com/docs) but this will get you started in about 30 seconds:

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

Run `caddy` from that directory, and it will automatically use that Caddyfile to configure itself.

That simple file enables compression, allows directory browsing (for folders without an index file), serves clean URLs, hosts an echo server for WebSocket connections at /echo, logs accesses to access.log, and adds the coveted `Access-Control-Allow-Origin: *` header for all responses from some API.

Wow! Caddy can do a lot with just a few lines.

#### Defining multiple sites

You can run multiple sites from the same Caddyfile, too:

```
http://mysite.com,
http://www.mysite.com {
	redir https://mysite.com
}

https://mysite.com {
	tls mysite.crt mysite.key
	# ...
}
```

Note that the secure host will automatically be served with HTTP/2 if the client supports it.

For more documentation, please view [the website](https://caddyserver.com/docs). You may also be interested in the [developer guide](https://github.com/mholt/caddy/wiki) on this project's GitHub wiki.






## Contributing

**[Join us on Slack](https://gophers.slack.com/messages/caddy/)** to chat with other Caddy developers! ([Request an invite](http://bit.ly/go-slack-signup), then join the #caddy channel.)

This project would not be what it is without your help. Please see the [contributing guidelines](https://github.com/mholt/caddy/blob/master/CONTRIBUTING.md) if you haven't already.

Thanks for making Caddy -- and the Web -- better!

Special thanks to [![DigitalOcean](http://i.imgur.com/sfGr0eY.png)](https://www.digitalocean.com) for hosting the Caddy project.




## About the project

Caddy was born out of the need for a "batteries-included" web server that runs anywhere and doesn't have to take its configuration with it. Caddy took inspiration from [spark](https://github.com/rif/spark), nginx, lighttpd, Websocketd, and Vagrant, and provides a pleasant mixture of features from each of them.


*Twitter: [@mholt6](https://twitter.com/mholt6)*
