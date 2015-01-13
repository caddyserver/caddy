Meet caddy
===========

Caddy is a web server for your files like Apache, nginx, or lighttpd, but with different goals, features, and advantages.

*Note:* This software is pre-1.0. Don't use it in production -- yet. A lot will change, so please contribute your ideas by opening an issue!

### Run Caddy

To try Caddy now:

1. Build it
2. `cd` into a directory you want to serve
3. `./caddy` (or whatever the path is to the binary)

Caddy will, by default, serve the current working directory on [http://localhost:8080](http://localhost:8080) (the default port will change before 1.0).

### Configuring Caddy

If the current directory has a file called `Caddyfile`, it will be loaded and parsed and used as configuration. To configure Caddy, place a Caddyfile in the directory of your site.

A Caddyfile always starts with the address to bind to. The rest of the lines are configuration directives. Here's an example:

```
mydomain.com:80
gzip
ext .html
header /api Access-Control-Allow-Origin *
```

This simple file enables gzip compression, serves clean URLs (trying `.html` files under the hood), and adds the coveted "Access-Control-Allow-Origin: *" header to all requests starting with `/api`. Wow! Caddy can do a lot with just four lines.

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

It's that easy.



##### Table of Directives

| Directive | Syntax | Description | Example(s) |
|-----------|--------|-------------|------------|
| **root** | root *[path]* | Specifies the root folder from which to serve files. | `root /public/www` |
| **gzip** | gzip | Enables GZIP compression. | `gzip` |
| **log** | log *[what]* *[output-file]* *[format]* | Enables logging. Right now, only requests are logged. Default file is access.log. | `log requests /var/log/access.log "{time}: {method} for {url}"` |
| **rewrite** | rewrite *[from]* *[to]* | Internally rewrites a request from one path to another. | `rewrite /a /b` |
| **redir** | redir *[from]* *[to]* *[status]* | HTTP redirect with the given status code. | `redir /a /b 302` |
| **ext** | ext *[extensions...]* | Serve clean URLs by internally adding extensions to the requests. Extensions will be tried in the order listed. | `ext .html .htm .txt` |
| **import** | import *[file]* | Gets replaced with the contents of another file. Useful for sharing settings. | `import shared/common.conf` |
| **header** | header *[path]* *[header-name]* *[header-value]* -or- header *[path]* { *[header-name]* *[header-value]* ... } | Adds header(s) to responses of requests starting with the specified path. | `header / X-My-Header Foobar` |
| **tls** | tls *[cert-file]* *[key-file]* | Serves the site over SSL (actually TLS) using the given certificate and key files. | `tls ../ssl/cert.pem ../ssl/key.pem` |


This should get you started tinkering. Better docs are on the way, but the spec is changing so quickly at this point that docs may lag behind development for now.

### Contributing

Please submit your ideas in an issue or you can drop a quick [tweet to @mholt6](https://twitter.com/mholt6). Pull requests that fix bugs are totally welcome, too. (Pull requests for new features should be discussed in an issue first.) Thanks for being involved!
