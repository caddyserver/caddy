launchd service for macOS
=========================

This is a sample file for a *launchd* service on Mac.
Edit the paths and email in the plist file to match your info.

Start and Stop the Caddy launchd service using the following commands:

    $ launchctl load ~/Library/LaunchAgents/com.caddyserver.web.plist
    $ launchctl unload ~/Library/LaunchAgents/com.caddyserver.web.plist

More information can be found in this blogpost: [Running Caddy as a service on macOS X server](https://denbeke.be/blog/software/running-caddy-as-a-service-on-macos-os-x-server/)