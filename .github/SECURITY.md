# Security Policy

The Caddy project would like to make sure that it stays on top of all practically-exploitable vulnerabilities.

Some security problems are more the result of interplay between different components of the Web, rather than a vulnerability in the web server itself. Please report only vulnerabilities in the web server itself, as we cannot coerce the rest of the Web to be fixed (for example, we do not consider IP spoofing or BGP hijacks a vulnerability in the Caddy web server).

Please note that we consider publicly-registered domain names to be public information. This necessary in order to maintain the integrity of certificate transparency, public DNS, and other public trust systems.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :white_check_mark: (deprecating soon) |
| < 1.x   | :x:                |

## Reporting a Vulnerability

Please email Matt Holt (the author) directly: matt [at] lightcodelabs [dot com].

We'll need enough information to verify the bug and make a patch. It will speed things up if you suggest a working patch, such as a code diff, and explain why and how it works. Reports that are not actionable, do not contain enough information, are too pushy/demanding, or are not able to convince us that it is a viable and practical attack on the web server itself may be deferred to a later time or possibly ignored, resources permitting. Priority will be given to credible, responsible reports that are constructive, specific, and actionable. Thank you for understanding.

Please also understand that due to our nature as an open source project, we do not have a budget to award security bounties. We can only thank you.

If your report is valid and a patch is released, we will not reveal your identity by default. If you wish to be credited, please give us the name to use.

Thanks for responsibly helping Caddy&mdash;and thousands of websites&mdash;be more secure!
