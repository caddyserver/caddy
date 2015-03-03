Meet caddy
===========

Caddy is a web server for your files like Apache, nginx, or lighttpd, but with different goals, features, and advantages.

*Note:* This software is pre-1.0. Don't use it in production (yet).

### Features

- TLS
- FastCGI (mostly for PHP sites)
- WebSockets
- IPv4 and IPv6 support
- Gzip
- Custom headers
- Logging
- Rewrites
- Redirects
- Multi-core
- + more

Caddy is designed to be super-easy to use and configure.

### Run Caddy

1. Download or build it
2. `cd` into a directory you want to serve
3. `./caddy`

Caddy will, by default, serve the current working directory on [http://localhost:8080](http://localhost:8080) (the default port will change before version 1.0).

### Configuring Caddy

Use a Caddyfile to configure Caddy. If the current directory has a file called `Caddyfile`, it will be loaded and parsed and used as configuration.

A Caddyfile always starts with an address to bind to. The rest of the lines are configuration directives. Here's an example:

```
mydomain.com:80
gzip
ext .html
header /api Access-Control-Allow-Origin *
```

This simple file enables gzip compression, serves clean URLs, and adds the coveted `Access-Control-Allow-Origin: *` header to all requests starting with `/api`. Wow! Caddy can do a lot with just four lines.

Maybe you want to serve both HTTP and HTTPS. You can define multiple (virtual) hosts using curly braces:

```
mydomain.com:80 {
	gzip
	ext .html
	header /api Access-Control-Allow-Origin *
}

mydomain.com:443 {
	tls cert.pem key.pem
}
```

For more details, including which directives you can use to configure Caddy, see [the wiki](https://github.com/mholt/caddy/wiki).

Better documentation (and rigorous tests) are on their way as the program matures and leaves the experimental phase.


### Contributing

Please get involved! Before adding a new feature or changing existing behavior, open an issue to discuss it. For other non-breaking changes and bug fixes, pull requests are accepted. You can also drop a quick [tweet to @mholt6](https://twitter.com/mholt6) for quick feedback or comments.


### About the project

Caddy was born out of the need for a lightweight but configurable web server that didn't have to be "installed" and was readily available for any platform. Caddy took some inspiration from nginx, lighttpd, Websocketd, and Vagrant, and provides a pleasant mixture of the handy features from each of them. Caddy is suitable for use in both dev and production environments.
