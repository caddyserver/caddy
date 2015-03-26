Meet caddy
===========

Caddy is a web server for your files like Apache, nginx, or lighttpd, but with different goals, features, and advantages.

*Note:* This software is pre-1.0 and under rapid development. Don't use it in production (yet).

### Features

- HTTP/1.1 and HTTP/2
- TLS
- FastCGI
- WebSockets
- Markdown
- IPv4 and IPv6 support
- Gzip
- Custom headers
- Logging
- Rewrites
- Redirects
- Multi-core
- + more

Caddy is designed to be super-easy to use and configure. Full documentation coming soon.

### Run Caddy in 10 Seconds

1. Run `go get github.com/mholt/caddy`
2. `cd` into your website's directory
3. Run `caddy` (assumes `$GOPATH/bin` is in your `$PATH`)

Caddy will, by default, serve the current working directory on [http://localhost:8080](http://localhost:8080) (the default port will change before version 1.0).

When announced, there will be builds of Caddy available for all platforms.

### Configuring Caddy

Use a Caddyfile to configure Caddy. If the current directory has a file called `Caddyfile`, it will be loaded and parsed and used as configuration. Or you can specify the location of the file using the `-conf` flag.

A Caddyfile always starts with an address to bind to. The rest of the lines are configuration directives. Here's an example:

```
mydomain.com:80
gzip
ext .html
header /api Access-Control-Allow-Origin *
browse /files /home/myuser/template.tpl
```

This simple file enables compression, serves clean URLs, adds the coveted `Access-Control-Allow-Origin: *` header to all requests starting with `/api`, and enables file browsing in `/files` using a custom HTML template. Wow! Caddy can do a lot with just a few lines.

Maybe you want to serve both HTTP and HTTPS. You can define multiple (virtual) hosts using curly braces:

```
mydomain.com:80 {
	gzip
	ext .html
}

mydomain.com:443 {
	tls cert.pem key.pem
}
```

More documentation and rigorous tests are on their way as this program matures and leaves the experimental phase. Lots of refinements are planned and well on their way to becoming a reality.


### Contributing

Please get involved! Before adding a new feature or changing existing behavior, open an issue to discuss it. For non-breaking changes and bug fixes, pull requests are accepted. You can also drop a quick [tweet to @mholt6](https://twitter.com/mholt6) for quick feedback or comments.


### About the project

Caddy was born out of the need for a "batteries-included" web server that runs anywhere and doesn't have to take its configuration with it. Caddy took some inspiration from nginx, lighttpd, Websocketd, and Vagrant, and provides a pleasant mixture of features from each of them. Once announced, Caddy will be suitable for use in both dev and production environments.
