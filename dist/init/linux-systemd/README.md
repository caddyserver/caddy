# systemd service unit for caddy

Please do not hesitate to ask on
[caddyserver/support](https://gitter.im/caddyserver/support)
if you have any questions. Feel free to prepend to your question
the username of whoever touched the file most recently, for example
`@wmark re systemd: …`.

The provided file should work with systemd version 219 or later. It might work with earlier versions.
The easiest way to check your systemd version is to look at the version of the installed package
(e.g. 'sudo yum info systemd' on RedHat/Fedora systems).

## Quickstart

We will assume the following:

* that you want to run caddy as user `www-data` and group `www-data`, with UID and GID 33
* you are working from a non-root user account that can use 'sudo' to execute commands as root

Adjust as necessary or according to your preferences.

First, put the caddy binary in the system wide binary directory:

```bash
sudo cp /path/to/caddy /usr/local/bin
```

Give the caddy binary the execution permissions it will need to execute
as the www-data user:

```bash
XXXJOSH sudo chmod ??? /usr/local/bin/caddy
```

Give the caddy binary the ability to bind to privileged ports (e.g. 80, 443) as a non-root user:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
```

Set up the user, group, and directories that will be needed:

```bash
sudo groupadd -g 33 www-data
sudo useradd \
  -g www-data --no-user-group \
  --home-dir /var/www --no-create-home \
  --shell /usr/sbin/nologin \
  --system --uid 33 www-data

sudo mkdir /etc/caddy
sudo chown -R root:www-data /etc/caddy
sudo mkdir /etc/ssl/caddy
sudo chown -R www-data:root /etc/ssl/caddy
sudo chmod 0770 /etc/ssl/caddy
```

Place your caddy configuration file ("Caddyfile") in the proper directory:

```bash
sudo cp /path/to/Caddyfile /etc/caddy/
```

Create the home directory for the server and give it the appropriate permissions:

```bash
sudo mkdir /var/www
XXXJOSH sudo chmod ??? /var/www
```

Let's assume you have the contents of your website in a directory called 'example.com'.
Put your website into place for it to be served by caddy:

```bash
sudo cp -R example.com /var/www/
```

You'll need to explicity configure caddy to serve the site from this location by adding
the following to your Caddyfile:

```
example.com {
    root /var/www/example.com
    ...
}
```

Install the systemd service unit configuration file, reload the systemd daemon,
and start caddy:

```bash
sudo cp caddy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start caddy.service
```

Have the caddy service start automatically on boot if you like:

```bash
sudo systemctl enable caddy.service
```

If caddy didn't seem to start properly you can view the systemd log data to help
figure out what the problem is:

```bash
journalctl --boot -u caddy.service
```

Use `log stdout` and `errors stderr` in your Caddyfile to fully utilize systemd journaling.

If your GNU/Linux distribution does not use *systemd* with *journald* then check any logfiles in: `/var/log`

If you want to follow the latest logs from caddy you can do so like this:

```bash
journalctl -f -u caddy.service
```

You can make other certificates and private key files accessible to the `www-data` user with the following command:

```bash
setfacl -m user:www-data:r-- /etc/ssl/private/my.key
```
