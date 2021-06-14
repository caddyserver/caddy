# Security Policy

The Caddy project would like to make sure that it stays on top of all practically-exploitable vulnerabilities.


## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |
| < 1.x   | :x:                |


## Acceptable Scope

A security report must demonstrate a security bug in the source code from this repository.

Some security problems are the result of interplay between different components of the Web, rather than a vulnerability in the web server itself. Please only report vulnerabilities in the web server itself, as we cannot coerce the rest of the Web to be fixed (for example, we do not consider IP spoofing, BGP hijacks, or missing/misconfigured HTTP headers a vulnerability in the Caddy web server).

Vulnerabilities caused by misconfigurations are out of scope. Yes, it is entirely possible to craft and use a configuration that is unsafe, just like with every other web server; we recommend against doing that.

We do not accept reports if the steps imply or require a compromised system or third-party software, as we cannot control those. We expect that users secure their own systems and keep all their software patched. For example, if untrusted users are able to upload/write/host arbitrary files in the web root directory, it is NOT a security bug in Caddy if those files get served to clients; however, it _would_ be a valid report if a bug in Caddy's source code unintentionally gave unauthorized users the ability to upload unsafe files or delete files without relying on an unpatched system or piece of software.

Client-side exploits are out of scope. In other words, it is not a bug in Caddy if the web browser does something unsafe, even if the downloaded content was served by Caddy. (Those kinds of exploits can generally be mitigated by proper configuration of HTTP headers.) As a general rule, the content served by Caddy is not considered in scope because content is configurable by the site owner or the associated web application.

Security bugs in code dependencies are out of scope. Instead, if a dependency has patched a relevant security bug, please feel free to open a public issue or pull request to update that dependency in our code.


## Reporting a Vulnerability

We get a lot of difficult reports that turn out to be invalid. Clear, obvious reports tend to be the most credible (but are also rare).

First please ensure your report falls within the accepted scope of security bugs (above).

We'll need enough information to verify the bug and make a patch. To speed things up, please include:

- Most minimal possible config (without redactions!)
- Command(s)
- Precise HTTP requests (`curl -v` and its output please)
- Full log output (please enable debug mode)
- Specific minimal steps to reproduce the issue from scratch
- A working patch

Please DO NOT use containers, VMs, cloud instances or services, or any other complex infrastructure in your steps. Always prefer `curl` instead of web browsers.

We consider publicly-registered domain names to be public information. This necessary in order to maintain the integrity of certificate transparency, public DNS, and other public trust systems. Do not redact domain names from your reports. The actual content of your domain name affects Caddy's behavior, so we need the exact domain name(s) to reproduce with, or your report will be ignored.

It will speed things up if you suggest a working patch, such as a code diff, and explain why and how it works. Reports that are not actionable, do not contain enough information, are too pushy/demanding, or are not able to convince us that it is a viable and practical attack on the web server itself may be deferred to a later time or possibly ignored, depending on available resources. Priority will be given to credible, responsible reports that are constructive, specific, and actionable. (We get a lot of invalid reports.) Thank you for understanding.

When you are ready, please email Matt Holt (the author) directly: matt [at] lightcodelabs [dot com].

Please don't encrypt the email body. It only makes the process more complicated.

Please also understand that due to our nature as an open source project, we do not have a budget to award security bounties. We can only thank you.

If your report is valid and a patch is released, we will not reveal your identity by default. If you wish to be credited, please give us the name to use and/or your GitHub username. If you don't provide this we can't credit you.

Thanks for responsibly helping Caddy&mdash;and thousands of websites&mdash;be more secure!
