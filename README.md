[![Caddy](https://caddyserver.com/resources/images/caddy-boxed.png)](https://caddyserver.com)

[![Documentation](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/mholt/caddy)

Caddy is a lightweight, general-purpose web server for Windows, Mac, Linux, BSD, and [Android](https://github.com/mholt/caddy/wiki/Running-Caddy-on-Android). It is a capable alternative to other popular web servers.

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

NOTE: You will need Go **version 1.4** or greater

1. `$ go get github.com/mholt/caddy`
2. `cd` into your website's directory
3. Run `caddy` (assumes `$GOPATH/bin` is in your `$PATH`)

If you're tinkering, you can also use `go run main.go`.

By default, Caddy serves the current directory at [localhost:2015](http://localhost:2015). You can place a Caddyfile to configure Caddy for serving your site.

Caddy accepts some flags from the command line. Run `caddy -h` to view the help for flags.



#### Docker Container

Caddy is [available as a Docker container](https://registry.hub.docker.com/u/darron/caddy/).



#### 3rd-party libraries

Although Caddy's binaries are completely static, Caddy relies on some excellent libraries that really make the project possible.

- [bradfitz/http2](https://github.com/bradfitz/http2) for HTTP/2 support
- [russross/blackfriday](https://github.com/russross/blackfriday) for Markdown rendering
- [dustin/go-humanize](https://github.com/dustin/go-humanize) for pleasant times and sizes
- [flynn/go-shlex](https://github.com/flynn/go-shlex) to parse shell commands properly

This list may not be comprehensive, but [godoc.org](https://godoc.org/github.com/mholt/caddy) will list all packages that any given package imports.


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

This project gladly accepts contributions. Interested users are encouraged to get involved by opening issues with their ideas, questions, and bug reports. Bug reports should contain clear instructions to reproduce the problem and state expected behavior.

For small tweaks and bug fixes, feel free to submit pull requests at any time. For new features or to change existing behavior, please open an issue first to discuss it and claim it. This prevents overlapping efforts and also keeps the project in-line with its goals.

Thanks for making Caddy -- and the Web -- better!





## About the project

Caddy was born out of the need for a "batteries-included" web server that runs anywhere and doesn't have to take its configuration with it. Caddy took inspiration from nginx, lighttpd, Websocketd, and Vagrant, and provides a pleasant mixture of features from each of them.


*Twitter: [@mholt6](https://twitter.com/mholt6)*
