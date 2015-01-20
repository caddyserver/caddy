Meet caddy
===========

Caddy is a web server for your files like Apache, nginx, or lighttpd, but with different goals, features, and advantages.

*Note:* This software is pre-1.0. Don't use it in production -- yet. A lot will change, so feel free to contribute!

### Run Caddy

To try Caddy now:

1. Build it
2. `cd` into a directory you want to serve
3. `caddy` (assuming $GOPATH is in $PATH)

Caddy will, by default, serve the current working directory on [http://localhost:8080](http://localhost:8080) (the default port will change before 1.0).

### Configuring Caddy

If the current directory has a file called `Caddyfile`, it will be loaded and parsed and used as configuration. To configure Caddy, use a Caddyfile.

A Caddyfile always starts with the address to bind to. The rest of the lines are configuration directives. Here's an example:

```
mydomain.com:80
gzip
ext .html
header /api Access-Control-Allow-Origin *
```

This simple file enables gzip compression, serves clean URLs (tries `.html` files under the hood), and adds the coveted `Access-Control-Allow-Origin: *` header to all requests starting with `/api`. Wow! Caddy can do a lot with just four lines.

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

Please submit your ideas in an issue or you can drop a quick [tweet to @mholt6](https://twitter.com/mholt6). Pull requests that fix bugs are totally welcome, too. (Pull requests for new features should be discussed in an issue first.) Thanks for being involved!
