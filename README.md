Caddy 2 Development Branch
===========================

[![Build Status](https://dev.azure.com/mholt-dev/Caddy/_apis/build/status/Multiplatform%20Tests?branchName=v2)](https://dev.azure.com/mholt-dev/Caddy/_build/latest?definitionId=5&branchName=v2)
[![fuzzit](https://app.fuzzit.dev/badge?org_id=caddyserver-gh)](https://app.fuzzit.dev/orgs/caddyserver-gh/dashboard)

This is the development branch for Caddy 2. This code (version 2) is not yet feature-complete or production-ready, but is already being used in production, and we encourage you to deploy it today on sites that are not very visible or important so that it can obtain crucial experience in the field.

Please file issues to propose new features and report bugs, and after the bug or feature has been discussed, submit a pull request! We need your help to build this web server into what you want it to be. (Caddy 2 issues and pull requests receive priority over Caddy 1 issues and pull requests.)

**Caddy 2 is the web server of the Go community.** We are looking for maintainers to represent the community! Please become involved (issues, PRs, [our forum](https://caddy.community) etc.) and express interest if you are committed to being a collaborator on the Caddy project.


### Menu

- [Build from source](#build-from-source)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Full Documentation](#full-documentation)
- [List of Improvements](#list-of-improvements)
- [FAQ](#faq)


## Build from source

Requirements:

- [Go 1.13 or newer](https://golang.org/dl/)
- Do NOT disable [Go modules](https://github.com/golang/go/wiki/Modules) (`export GO111MODULE=auto`)

Download the `v2` source code:

```bash
$ git clone -b v2 "https://github.com/caddyserver/caddy.git"
```

Build:

```bash
$ cd caddy/cmd/caddy/
$ go build
```

That will put a `caddy(.exe)` binary into the current directory. You can move it into your PATH or use `go install` to do that automatically (assuming `$GOPATH/bin` is already in your PATH). You can also use `go run main.go` for quick, temporary builds while developing.

The initial build may be slow as dependencies are downloaded. Subsequent builds should be very fast. If you encounter any Go-module-related errors, try clearing your Go module cache (`$GOPATH/pkg/mod`) and Go package cache (`$GOPATH/pkg`) and read [the Go wiki page about modules for help](https://github.com/golang/go/wiki/Modules). If you have issues with Go modules, please consult the Go community for help. But if there is an actual error in Caddy, please report it to us.


## Quick Start

(Until the stable 2.0 release, there may be breaking changes in v2, please be aware!)

These instructions assume an executable build of Caddy 2 is named `caddy` in the current folder. If it's in your PATH, you may omit the path to the binary (`./`).

Start Caddy:

```bash
$ ./caddy start
```

There are no config files with Caddy 2. Instead, you POST configuration to it:

```bash
$ curl -X POST "http://localhost:2019/load" \
    -H "Content-Type: application/json" \
    -d @- << EOF
    {
        "apps": {
            "http": {
                "servers": {
                    "example": {
                        "listen": ["127.0.0.1:2080"],
                        "routes": [
                            {
                                "handle": [{
                                    "handler": "file_server",
                                    "browse": {}
                                }]
                            }
                        ]
                    }
                }
            }
        }
    }
EOF
```

Now visit http://localhost:2080 in your browser and you will see the contents of the current directory displayed.

To change Caddy's configuration, simply POST a new payload to that endpoint. Config changes are extremely lightweight and efficient, and should be graceful on all platforms -- _even Windows_.

Updating configuration using heredoc can be tedious, so you can still use a config file if you prefer. Put your configuration in any file (`caddy.json` for example) and then POST that instead:

```bash
$ curl -X POST "http://localhost:2019/load" \
    -H "Content-Type: application/json" \
    -d @caddy.json
```

Or you can tell Caddy to load its configuration from a file in the first place (this simply does the work of the above curl command for you):

```bash
$ ./caddy start --config caddy.json
```

To stop Caddy:

```bash
$ ./caddy stop
```

Note that this will stop any process named the same as `os.Args[0]`.

For other commands, please see [the Caddy 2 documentation](https://github.com/caddyserver/caddy/wiki/v2:-Documentation).

### Caddyfile

Caddy 2 can be configured with a Caddyfile, much like in v1, for example:

```plain
example.com

try_files {path}.html {path}
encode gzip zstd
reverse_proxy /api  localhost:9005
php_fastcgi   /blog unix//path/to/socket
file_server
```

Instead of being its primary mode of configuration, an internal _config adapter_ adapts the Caddyfile to Caddy's native JSON structure. You can see it in action with the [`adapt` command](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#adapt):

```bash
$ ./caddy adapt --config path/to/Caddyfile --adapter caddyfile --pretty
```

If you just want to run Caddy with your Caddyfile directly, the CLI wraps this up for you nicely. Either of the following commands:

```bash
$ ./caddy start
$ ./caddy run
```

will use your Caddyfile if it is called `Caddyfile` in the current directory.

If your Caddyfile is somewhere else, you can still use it:

```bash
$ ./caddy start|run --config path/to/Caddyfile --adapter caddyfile
```

[Learn more about the Caddyfile in v2.](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#caddyfile-adapter)


## Configuration

Caddy 2 exposes an unprecedented level of control compared to any web server in existence. In Caddy 2, you are usually setting the actual values of the initialized types in memory that power everything from your HTTP handlers and TLS handshakes to your storage medium. Caddy 2 is also ridiculously extensible, with a module system that makes vast improvements over Caddy 1's plugin system.

Nearly all of Caddy 2's configuration is contained in a single config document, rather than being spread across CLI flags and env variables and a configuration file as with other web servers (and Caddy 1).

To wield the power of this design, you need to know how the config document is structured. Please see the [the Caddy 2 documentation in our wiki](https://github.com/caddyserver/caddy/wiki/v2:-Documentation) for details about Caddy's config structure.

Configuration is normally given to Caddy through an API endpoint, which is likewise documented in the wiki pages. However, you can also use config files of various formats with [config adapters](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#config-adapters).


## Full Documentation

Caddy 2 is very much in development, so the documentation is an ongoing WIP, but the latest will be in our wiki for now:

**https://github.com/caddyserver/caddy/wiki/v2:-Documentation**

Note that breaking changes are expected until the stable 2.0 release.


## List of Improvements

The following is a non-comprehensive list of significant improvements over Caddy 1. Not everything in this list is finished yet, but they will be finished or at least will be possible with Caddy 2:

- Centralized configuration. No more disparate use of environment variables, config files (potentially multiple!), CLI flags, etc.
- REST API. Control Caddy with HTTP requests to an administration endpoint. Changes are applied immediately and efficiently.
- Dynamic configuration. Any and all specific config values can be modified directly through the admin API with a REST endpoint.
    - Change only specific configuration settings instead of needing to specify the whole config each time. This makes it safe and easy to change Caddy's config with manually-crafted curl commands, for example.
- No configuration files. Except optionally to bootstrap its configuration at startup. You can still use config files if you wish, and we expect that most people will.
- Export the current Caddy configuration with an API GET request.
- Silky-smooth graceful reloads. Update the configuration up to dozens of times per second with no dropped requests and very little memory cost. Our unique graceful reload technology is lighter and faster **and works on all platforms, including Windows**.
- An embedded scripting language! Caddy2 has native Starlark integration. Do things you never thought possible with higher performance than Lua, JavaScript, and other VMs. Starlark is expressive, familiar (dialect of Python), _almost_ Turing-complete, and highly efficient. (We're still improving performance here.)
- Using [XDG standards](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html#variables) instead of dumping all assets in `$HOME/.caddy`.
- Caddy plugins are now called "Caddy modules" (although the terms "plugin" and "module" may be used interchangeably). Caddy modules are a concept unrelated [Go modules](https://github.com/golang/go/wiki/Modules), except that Caddy modules may be implemented by Go modules. Caddy modules are centrally-registered, properly namespaced, and generically loaded & configured, as opposed to how scattered and unorganized Caddy 1-era plugins are.
- Modules are easier to write, since they do not have to both deserialize their own configuration from a configuration DSL and provision themselves like plugins did. Modules are initialized pre-configured and have the ability to validate the configuration and perform provisioning steps if necessary.
- Can specify different storage mechanisms in different parts of the configuration, if more than one is needed.
- "Top-level" Caddy modules are simply called "apps" because literally any long-lived application can be served by Caddy 2.
- Even more of Caddy is made of modules, allowing for unparalleled extensibility, flexibility, and control. Caddy 2 is arguably the most flexible, extensible, programmable web server ever made.
- TLS improvements!
	- TLS configuration is now centralized and decoupled from specific sites
	- A single certificate cache is used process-wide, reducing duplication and improving memory use
	- Customize how to manage each certificate ("automation policies") based on the hostname
	- Automation policy doesn't have to be limited to just ACME - could be any way to manage certificates
	- Fine-grained control over TLS handshakes
	- If an ACME challenge fails, other enabled challenges will be tried (no other web server does this)
    - TLS Session Ticket Ephemeral Keys (STEKs) can be rotated in a cluster for increased performance (no other web server does this either!)
    - Ability to select a specific certificate per ClientHello given multiple qualifying certificates
    - Provide TLS certificates without persisting them to disk; keep private keys entirely in memory
	- Certificate management at startup is now asynchronous and much easier to use through machine reboots and in unsupervised settings
- All-new HTTP server core
	- Listeners can be configured for any network type, address, and port range
	- Customizable TLS connection policies
	- HTTP handlers are configured by "routes" which consist of matcher and handler components. Match matches an HTTP request, and handle defines the list of handlers to invoke as a result of the match.
	- Some matchers are regular expressions, which expose capture groups to placeholders.
	- New matchers include negation and matching based on remote IP address / CIDR ranges.
    - Placeholders are vastly improved generally
	- Placeholders (variables) are more properly namespaced.
	- Multiple routes may match an HTTP request, creating a "composite route" quickly on the fly.
	- The actual handler for any given request is its composite route.
	- User defines the order of middlewares (careful! easy to break things).
	- Adding middlewares no longer requires changes to Caddy's code base (there is no authoritative list).
	- Routes may be marked as terminal, meaning no more routes will be matched.
	- Routes may be grouped so that only the first matching route in a group is applied.
	- Requests may be "re-handled" if they are modified and need to be sent through the chain again (internal redirect).
	- Vastly more powerful static file server, with native content-negotiation abilities
    - Done away with URL-rewriting hacks often needed in Caddy 1
	- Highly descriptive/traceable errors
	- Very flexible error handling, with the ability to specify a whole list of routes just for error cases
	- The proxy has numerous improvements, including dynamic backends and more configurable health checks
	- FastCGI support integrated with the reverse proxy
	- More control over automatic HTTPS: disable entirely, disable only HTTP->HTTPS redirects, disable only cert management, and for certain names, etc.
    - Use Starlark to build custom, dynamic HTTP handlers at request-time
        - We are finding that -- on average -- Caddy 2's Starlark handlers are ~1.25-2x faster than NGINX+Lua.

And a few major features still being worked on:

- Logging
- Kubernetes ingress controller (mostly done, just polishing it -- and it's amazing)
- More config adapters. Caddy's native JSON config structure is powerful and complex. Config adapters upsample various formats to Caddy's native config. There are already adapters for Caddyfile, JSON 5, and JSON-C. Planned are NGINX config, YAML, and TOML. The community might be interested in building Traefik and Apache config adapters!



## FAQ

### How do I configure Caddy 2?

Caddy's primary mode of configuration is a REST API, which accepts a JSON document. The JSON structure is described [in the wiki](https://github.com/caddyserver/caddy/wiki/v2:-Documentation). The advantages of exposing this low-level structure are 1) it has near-parity with actual memory initialization, 2) it allows us to offer wrappers over this configuration to any degree of convenience that is needed, and 3) it performs very well under rapid config changes.

Basically, you will [start Caddy](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#start), then [POST a JSON config to its API endpoint](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#post-load).

Although this makes Caddy 2 highly programmable, not everyone will want to configure Caddy via JSON with an API. Sometimes we just want to give Caddy a simple, static config file and have it do its thing. That's what **[config adapters](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#config-adapters)** are for! You can configure Caddy more ways than one, depending on your needs and preferences. See the next questions that explain this more.

### Caddy 2 feels harder to use. How is this an improvement over Caddy 1?

Caddy's ease of use is one of the main reasons it is special. We are not taking that away in Caddy 2, but first we had to be sure to tackle the fundamental design limitations with Caddy 1. Usability can then be layered on top. This approach has several advantages which we discuss in the next question.

### What about the Caddyfile; are there easier ways to configure Caddy 2?

Yes! Caddy's native JSON configuration via API is nice when you are automating config changes at scale, but if you just have a simple, static configuration in a file, you can do that too with the [Caddyfile](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#caddyfile-adapter).

The v2 Caddyfile is very similar to the v1 Caddyfile, but they are not compatible. Several improvements have been made to request matching and directives in v2, giving you more power with less complexity and fewer inconsistencies.

Caddy's default _config adapter_ is the Caddyfile adapter. This takes a Caddyfile as input and [outputs the JSON config](https://github.com/caddyserver/caddy/wiki/v2:-Documentation#adapt). You can even run Caddy directly without having to see or think about the underlying JSON config.

The following _config adapters_ are already being built or plan to be built:

- Caddyfile
- JSON 5
- JSON-C
- nginx
- YAML
- TOML
- any others that the community would like to contribute

Config adapters allow you to configure Caddy not just one way but _any_ of these ways. For example, you'll be able to bring your existing NGINX config to Caddy and it will spit out the Caddy config JSON you need (to the best of its ability). How cool is that! You can then easily tweak the resulting config by hand, if necessary.

All config adapters vary in their theoretical expressiveness; that is, if you need more advanced configuration you'll have to drop down to the JSON config, because the Caddyfile or an nginx config may not be expressive enough.

However, we expect that most users will be able to use the Caddyfile (or another easy config adapter) exclusively for their sites.

### Why JSON for configuration? Why not _&lt;any other serialization format&gt;_?

We know there might be strong opinions on this one. Regardless, for Caddy 2, we've decided to go with JSON. If that proves to be a fatal mistake, then Caddy 3 probably won't use JSON.

JSON may not be the fastest, the most compact, the easiest to write, serialization format that exists. But those aren't our goals. It has withstood the test of time and checks all our boxes.

- It is almost entirely ubiquitous. JSON works natively in web browsers and has mature libraries in pretty much every language.
- It is human-readable (as opposed to a binary format).
- It is easy to tweak by hand. Although composing raw JSON by hand is not awesome, this will not be mainstream once our config adapters are done.
- It is generally easy to convert other serializations or config formats into JSON, as opposed to the other way around.
- Even though JSON deserialization is not fast per-se, that kind of performance is not really a concern since config reloads are not the server's hottest path like HTTP request handling or TLS handshakes are. Even with JSON, Caddy 2 can handle dozens of config changes per second, which is probably plenty for now.
- It maps almost 1:1 to the actual, in-memory values that power your HTTP handlers and other parts of the server (no need to parse a config file with some arbitrary DSL and do a bunch of extra pre-processing).

Ultimately, we think all these properties are appropriate -- if not ideal -- for a web server configuration.

If you're still not happy with the choice of JSON, feel free to contribute a config adapter of your own choice!

Or just use YAML or TOML, which seamlessly translate to JSON.

### JSON is declarative; what if I need more programmability (i.e. imperative syntax)?

NGINX also realized the need for imperative logic in declarative configs, so they tried "if" statements, [but it was a bad idea](https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/).

We have good news. Caddy 2 can give you the power of imperative logic without the perils of mixing declarative and imperative config such as befell NGINX. We do this by allowing embedded imperative syntax awithin the Caddy's declarative config.

Caddy 2's configuration is declarative because configuration is very much declarative in nature. Configuration is a tricky medium, as it is read and written by both computers and humans. Computers use it, but humans constantly refer to it and update it. Declarative syntaxes are fairly straightforward to make sense of, whereas it is difficult to reason about imperative logic.

However, sometimes computation is useful, and in some cases, the only way to express what you need. This can be illustrated really well in the simple case of trying to decide whether a particular HTTP middleware should be invoked as part of an HTTP request. A lot of the time, such logic is as simple as: "GET requests for any path starting with /foo/bar", which can be expressed declaratively in JSON:

```json
{
	"method": "GET",
	"path": "/foo/bar"
}
```

But what if you need to match /foo/bar OR /topaz? How do you express that OR clause? Maybe an array:

```json
{
	"method": ["GET"],
	"path": ["/foo/bar", "/topaz"]
}
```

Now what if you need add a NOT or AND clause? JSON quickly tires out. As you learn about Caddy 2's request matching, you will see how we handled this. Caddy 2's JSON gives you the ability to express moderately-complex logic such as:

```js
// this is not actual Caddy config, just logic pseudocode
IF (Host = "example.com")
	OR (Host = "sub.example.com" AND Path != "/foo/bar")
```

Already, this is more expressive power than most web servers offer with their native config, yet Caddy 2 offers this in JSON.

But in most web servers, to make logic this complex feasible, you'll generally call out to Lua or some extra DSL. For example, in NGINX you could use a Lua module to express this logic. Traefik 2.0 has [yet another kind of clunky-looking custom DSL](https://blog.containo.us/back-to-traefik-2-0-2f9aa17be305#d22e) just for this.

Caddy 2 solves this in a novel way with [Starlark expressions](https://godoc.org/go.starlark.net/starlark#Eval). Starlark is a familiar dialect of Python! So, no new DSLs to learn and no VMs to slow things down:

```python
req.host == 'example.com' ||
	(req.host == 'sub.example.com' && req.path != '/foo/bar')
```

Starlark performs at least as well as NGINX+Lua (more performance tests ongoing, as well as optimizations to make it even faster!) and because it's basically Python, it's familiar and easy to use.

In summary: Caddy 2 config is declarative, but can be imperative where that is useful.

### What is Caddy 2 licensed as?

Caddy 2 is licensed under the Apache 2.0 open source license. There are no official Caddy 2 distributions that are proprietary.

### Does Caddy 2 have telemetry?

No. There was not enough academic interest to continue supporting it. If telemetry does get added later, it will not be on by default or will be vastly reduced in its scope.

## Does Caddy 2 use HTTPS by default?

Yes. HTTPS is automatic and enabled by default when possible, just like in Caddy 1. Basically, if your HTTP routes specify a `host` matcher with qualifying domain names, those names will be enabled for automatic HTTPS. Automatic HTTPS is disabled for domains which match certificates that are manually loaded by your config.

## How do I avoid Let's Encrypt rate limits with Caddy 2?

As you are testing and developing with Caddy 2, you should use test ("staging") certificates from Let's Encrypt to avoid rate limits. By default, Caddy 2 uses Let's Encrypt's production endpoint to get real certificates for your domains, but their [rate limits](https://letsencrypt.org/docs/rate-limits/) forbid testing and development use of this endpoint for good reasons. You can switch to their [staging endpoint](https://letsencrypt.org/docs/staging-environment/) by adding the staging CA to your automation policy in the `tls` app:

```json
"tls": {
	"automation": {
		"policies": [
			{
				"management": {
					"module": "acme",
					"ca": "https://acme-staging-v02.api.letsencrypt.org/directory"
				}
			}
		]
	}
}
```

Or with the Caddyfile, using a global options block at the top:

```
{
	acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}
```

## Can we get some access controls on the admin endpoint?

Yeah, that's coming. For now, you can use a permissioned unix socket for some basic security.
