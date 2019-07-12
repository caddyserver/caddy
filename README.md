Caddy 2 Development Branch
===========================

This is the development branch for Caddy 2. This code (version 2) is not yet feature-complete or production-ready, but is already being used in production, and we encourage you to deploy it today on sites that are not very visible or important so that it can obtain crucial experience in the field.

Please file issues to propose new features and report bugs, and after the bug or feature has been discussed, submit a pull request! We need your help to build this web server into what you want it to be. (Caddy 2 issues and pull requests will usually receive priority over Caddy 1 issues and pull requests.)

**We want Caddy 2 to be the web server of the Go community!** We are looking for maintainers to represent the community. Please become involved (issues, PRs, [our forum](https://caddy.community) etc.) and express interest if you are committed to being a collaborator on the Caddy project.


### Menu

- [Install](#install)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Full Documentation](#full-documentation)
- [List of Improvements](#list-of-improvements)
- [FAQ](#faq)


## Install

Requirements:

- [Go 1.12 or newer](https://golang.org/dl/)
- [Go modules](https://github.com/golang/go/wiki/Modules) enabled: `export GO111MODULE=on`

Download source code:

```bash
$ git clone -b v2 "https://github.com/caddyserver/caddy.git"
```

Build:

```bash
$ cd caddy/cmd/caddy/
$ go build
```

That will put a `caddy(.exe)` binary into the current directory. You can move it into your PATH or use `go install` to do that automatically (assuming `$GOPATH/bin` is already in your PATH). You can also use `go run main.go` for quick, temporary builds while developing.

The initial build may be slow as dependencies are downloaded. Subsequent builds should be very fast. If you encounter any Go-module-related errors, try clearing your Go module cache (`$GOPATH/pkg/mod`) and read [the Go wiki page about modules for help](https://github.com/golang/go/wiki/Modules).


## Quick Start

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


## Configuration

Caddy 2 exposes an unprecedented level of control compared to any web server in existence. In Caddy 2, you are usually setting the actual values of the initialized types in memory that power everything from your HTTP handlers and TLS handshakes to your storage medium. Caddy 2 is also ridiculously extensible, with a module system that makes vast improvements over Caddy 1's plugin system.

Nearly all of Caddy 2's configuration is contained in a single config document, rather than being spread across CLI flags and env variables and a configuration file as with other web servers (and Caddy 1).

To wield the power of this design, you need to know how the config document is structured. Please see the [the Caddy 2 documentation in our wiki](https://github.com/caddyserver/caddy/wiki/v2:-Documentation) for details about Caddy's config structure.

Configuration is normally given to Caddy through an API endpoint, which is likewise documented in the wiki pages.


## Full Documentation

Caddy 2 is very much in development, so the documentation is an ongoing WIP, but the latest will be in our wiki for now:

**https://github.com/caddyserver/caddy/wiki/v2:-Documentation**


## List of Improvements

The following is a non-comprehensive list of significant improvements over Caddy 1. Not everything in this list is finished yet, but they will be finished or at least will be possible with Caddy 2 or Caddy Enterprise:

- Centralized configuration. No more disparate use of environment variables, config files (potentially multiple!), CLI flags, etc.
- REST API. Control Caddy with HTTP requests to an administration endpoint. Changes are applied immediately and efficiently.
- Dynamic configuration. Any and all specific config values can be modified directly through the admin API with a REST endpoint.
    - Enterprise: Change only specific configuration settings instead of needing to specify the whole config each time. This makes it safe and easy to change Caddy's config with manually-crafted curl commands, for example.
- No configuration files. Except optionally to bootstrap its configuration at startup. You can still use config files if you wish, and we expect that most people will.
- Enterprise: Export the current Caddy configuration with an API GET request.
- Silky-smooth graceful reloads. Update the configuration up to dozens of times per second with no dropped requests and very little memory cost. Our unique graceful reload technology is lighter and faster **and works on all platforms, including Windows**.
- An embedded scripting language! Caddy2 has native Starlark integration. Do things you never thought possible with higher performance than Lua, JavaScript, and other VMs. Starlark is expressive, familiar (dialect of Python), _almost_ Turing-complete, and highly efficient. (We're still improving performance here.)
- Using [XDG standards](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html#variables) instead of dumping all assets in `$HOME/.caddy`.
- Caddy plugins are now called "Caddy modules" (although the terms "plugin" and "module" may be used interchangably). Caddy modules are a concept unrelated [Go modules](https://github.com/golang/go/wiki/Modules), except that Caddy modules may be implemented by Go modules. Caddy modules are centrally-registered, properly namespaced, and generically loaded & configured, as opposed to how scattered and unorganized Caddy 1-era plugins are.
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
    - Enterprise: TLS Session Ticket Ephemeral Keys (STEKs) can be rotated in a cluster for increased performance (no other web server does this either!)
    - Enterprise: Ability to select a specific certificate per ClientHello given multiple qualifying certificates
    - Enterprise: Provide TLS certificates without persisting them to disk; keep private keys entirely in memory
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
	- More control over automatic HTTPS: disable entirely, disable only HTTP->HTTPS redirects, disable only cert management, and for certain names, etc.
    - Enterprise: Use Starlark to build custom, dynamic HTTP handlers at request-time
        - We are finding that -- on average -- Caddy 2's Starlark handlers are ~1.25-2x faster than NGINX+Lua.

And a few major features still being worked on:

- Logging
- More powerful, dynamic reverse proxy
- Kubernetes ingress controller (mostly done, just polishing it -- and it's amazing)
- Config adapters. Caddy's native JSON config structure is powerful and complex. Config adapters upsample various formats to Caddy's native config. Planned adapters include Caddyfile, NGINX config, YAML, and TOML. The community might be interested in building Traefik and Apache config adapters!



## FAQ

### How do I configure Caddy 2?

First you need to build a configuration document, which is in JSON. You may wish to write in YAML or TOML and then convert to JSON, that is fine too. The structure is described [in the wiki](https://github.com/caddyserver/caddy/wiki/v2:-Documentation).

Once you have your configuration document ready, you need to give it to Caddy. This can be done at startup or while it's running. See the instructions above for how to do this.

### Caddy 2 feels harder to use. How is this an improvement over Caddy 1?

Caddy's ease of use is one of the main reasons it is special. We are not taking that away in Caddy 2, but first we had to be sure to tackle the fundamental design limitations with Caddy 1. Usability can then be layered on top. This approach has several advantages which we discuss in the next question.

### What about the Caddyfile; are there easier ways to configure Caddy 2?

Yes; or there will be, soon. Caddy's native configuration language is JSON (see next question), but the advantage of exposing this low-level structure that has near-parity with actual memory initialization allows us to offer wrappers over this configuration to any degree of flexibility that is needed without suffering a significant performance hit during reloads.

The following _config adapters_ are already being built or plan to be built:

- Caddyfile
- nginx
- YAML
- TOML
- any others that the community would like to contribute

When finished, config adapters will allow you to configure Caddy not just one way but _any_ of these ways. For example, you'll be able to bring your existing NGINX config to Caddy and it will spit out the Caddy config JSON you need (to the best of its ability). How cool is that! You can then easily tweak the resulting config by hand, if necessary.

All config adapters vary in their theoretical expressiveness; that is, if you need more advanced configuration you'll have to drop down to the JSON config, because the Caddyfile or an nginx config may not be expressive enough.

However, we expect that most users will be able to use the Caddyfile (or another easy config adapter) exclusively for their sites.

(The Caddyfile will be upgraded from version 1 to support common use cases that are a bit painful with the current v1 Caddyfile.)

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

We have good news.

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

### What will Caddy 2 be licensed as?

Caddy 2 is licensed under the Apache 2.0 open source license. There are no official Caddy 2 distributions that are proprietary.

### What is Caddy Enterprise?

Caddy Enterprise is our web server for businesses that need more advanced features for higher scalability and easier management of clusters. It is built on the same core as Caddy 2, but licensed exclusively to enterprise customers who need it. It includes:

- a web UI
- performance improvements within a cluster
- advanced TLS controls
- fine-grained config changes (i.e. ability to change only certain parts of the configuration)
- training and support
- advanced HTTP handlers for authentication, metrics, debugging, and more
- dynamic HTTP handlers and TLS handshakes with Starlark

Caddy 2 and Caddy Enterprise offer equal levels of security.

### Does Caddy 2 have telemetry?

No. There was not enough academic interest to continue supporting it. If telemetry does get added later, it will not be on by default or will be vastly reduced in its scope so that it simply helps the community gain an understanding of how widely Caddy is deployed (i.e. counts of servers running, number of requests/connections handled, etc, but no actual content; just counts).

## Does Caddy 2 use HTTPS by default?

Yes. HTTPS is automatic and enabled by default when possible, just like in Caddy 1. Basically, if your HTTP routes specify a `host` matcher with qualifying domain names, those names will be enabled for automatic HTTPS.

## I'm getting HTTPS errors with Caddy 2. The certificates aren't valid?

During development, Caddy 2 uses Let's Encrypt's staging endpoint to avoid rate limit issues, so the certificates are not trusted. You can force the production endpoint if you are confident that your setup is correct and will last a while. You can add a catch-all automation policy to your `tls` app that specifies the production CA endpoint:

```json
"tls": {
	"automation": {
		"policies": [
			{
				"management": {
					"module": "acme",
					"ca": "https://acme-v02.api.letsencrypt.org/directory"
				}
			}
		]
	}
}
```

## Can we get some access controls on the admin endpoint?

Yeah, that's coming.

