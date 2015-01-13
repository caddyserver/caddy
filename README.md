Meet caddy
===========

Caddy is a web server for your files, much like Apache, nginx, or lighttpd, but with different goals, features, and advantages.

*Note:* This software is pre-1.0. Don't use it in production -- yet. Much will be changing, so please contribute your ideas by opening an issue!

### Run Caddy

To try Caddy now:

1. Build it
2. Put it in your $PATH
3. `cd` into a directory you want to serve
4. `$ caddy`

Caddy will, by default, serve the current working directory on http://localhost:8080 (the default port will change before 1.0).

### Configuring Caddy

If the current directory has a file called `Caddyfile`, it will be loaded and parsed and used as configuration. To configure Caddy, place a Caddyfile in the directory of your site.

A Caddyfile should always start with the address to bind to. The rest of the lines are directives which configure the server. Here's an example:

```
mydomain.com:80

gzip
ext .html
header /api Access-Control-Allow-Origin *
```

This file enables gzip compression, assumes a default file extension of `.html` (so you can serve clean URLs), and adds the coveted "Access-Control-Allow-Origin: *" header to all requests starting with `/api`. Wow! Caddy can do a lot with just four lines of config.

Maybe you want to serve both HTTP and HTTPS. Server, or virtual host, blocks can be defined using curly braces:

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

That easily, we also serve HTTPS on port 443 using the supplied server certificate and key files.

Directives that are supported:

- *root* [path]
- *gzip*
- *log* requests [output-file] [log-format]
- *rewrite* [from] [to]
- *redir* [from] [to] [status]
- *ext* [list of extensions to try if request doesn't have one]
- *header* [path] [header-name] [header-value]
- *tls* [cert-file] [key-file]

This should get you started tinkering. Better docs are on the way, but the spec is changing so quickly at this point that updated docs may lag behind development for now.

### Contributing

Please submit your ideas in an issue or you can drop a quick [tweet to @mholt6](https://twitter.com/mholt6). Pull requests that fix bugs are totally welcome, too. (Pull requests for new features should be discussed in an issue first.) Thanks for being involved!