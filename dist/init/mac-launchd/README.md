launchd service for macOS
=========================

This is a working sample file for a *launchd* service on Mac, which should be placed here:

```bash
/Library/LaunchDaemons/com.caddyserver.web.plist
```

To create the proper directories as used in the example file:

```bash
sudo mkdir -p /etc/caddy /etc/ssl/caddy /var/log/caddy /usr/local/bin /var/tmp /srv/www/localhost
sudo touch /etc/caddy/Caddyfile
sudo chown root:wheel -R /usr/local/bin/caddy /Library/LaunchDaemons/
sudo chown _www:_www -R /etc/caddy /etc/ssl/caddy /var/log/caddy
sudo chmod 0750 /etc/ssl/caddy
```

Create a simple web page and Caddyfile

```bash
sudo bash -c 'echo "Hello, World!" > /srv/www/localhost/index.html'
sudo bash -c 'echo "http://localhost {
    root /srv/www/localhost
}" >> /etc/caddy/Caddyfile'
```

Start and Stop the Caddy launchd service using the following commands:

```bash
launchctl load /Library/LaunchDaemons/com.caddyserver.web.plist
launchctl unload /Library/LaunchDaemons/com.caddyserver.web.plist
```

To start on every boot use the `-w` flag (to write):

```bash
launchctl load -w /Library/LaunchAgents/com.caddyserver.web.plist
```

More information can be found in this blogpost: [Running Caddy as a service on macOS X server](https://denbeke.be/blog/software/running-caddy-as-a-service-on-macos-os-x-server/)
