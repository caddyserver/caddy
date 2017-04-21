# systemd Service Unit for Caddy

Please do not hesitate to ask on
[caddyserver/support](https://gitter.im/caddyserver/support)
if you have any questions. Feel free to prepend to your question
the username of whoever touched the file most recently, for example
`@wmark re systemd: …`.

The provided file should work with systemd version 229 or later.
The easiest way to check your systemd version is to look at the version of the installed package
(e.g. 'sudo dpkg --status systemd | grep Version' on Debian/Ubuntu or 'sudo yum info systemd' on RedHat/Fedora systems).

We will assume the following:

* that you want to run caddy as user `www-data` and group `www-data`
* you are working from a non-root user account that can use 'sudo' to execute commands as root

Adjust as necessary or according to your preferences.

## Install

Install Caddy to `/usr/local/bin`:

```bash
# Note: change amd64 to386,  arm5, arm6, or arm7 as necessary,
#       also you can add plugins as desired
curl --fail --silent --show-error --location \
  'https://caddyserver.com/download/linux/amd64?plugins=' --output /tmp/caddy.tar.gz

mkdir -p /tmp/caddy-package/
tar xvf /tmp/caddy.tar.gz -C /tmp/caddy-package/
sudo chmod 755 /tmp/caddy-package/caddy
sudo chown root:root /tmp/caddy-package/caddy
sudo mv /tmp/caddy-package/caddy /usr/local/bin/
```

Then install `/etc/systemd/system/caddy.service` and `/etc/tmpfiles.d/caddy.conf`:

```
curl --fail --silent --show-error --location --remote-name-all \
  https://raw.githubusercontent.com/mholt/caddy/master/dist/init/linux-systemd/caddy.service
curl --fail --silent --show-error --location --remote-name-all \
  https://raw.githubusercontent.com/mholt/caddy/master/dist/init/linux-systemd/caddy.conf

sudo chown root:www-data caddy.service
sudo chown root:www-data caddy.conf

sudo chmod 0755 caddy.service
sudo chmod 0755 caddy.conf

sudo mv caddy.service /etc/systemd/system/
sudo mv caddy.conf /etc/tmpfiles.d/
```

Have the caddy service start automatically on boot if you like:

```bash
sudo systemctl daemon-reload
sudo systemctl start caddy.service
sudo systemctl enable caddy.service
```

If caddy doesn't seem to start properly you can view the log data to help figure out what the problem is:

```bash
journalctl --pager-end --catalog --unit caddy.service
```

Use `log stdout` and `errors stderr` in your Caddyfile to fully utilize systemd journaling.

If your GNU/Linux distribution does not use *journald* with *systemd* then check any logfiles in `/var/log`.

If you want to follow the latest logs from caddy you can do so like this:

```bash
journalctl --follow --unit caddy.service
```

## Directory Structure

We expect that your directory structure for your caddy installation looks like this:

```
/usr/local/bin/caddy
/etc/caddy/Caddyfile
/etc/ssl/caddy/acme
/etc/ssl/caddy/ocsp
/etc/tmpfiles.d/caddy.conf
/srv/www/localhost
/var/log/caddy
```

Here's how you can ensure that what we expect matches your reality:

```
# Optionally create the directories
sudo mkdir -p /etc/caddy
sudo mkdir -p /etc/ssl/caddy
sudo mkdir -p /srv/www/localhost
sudo mkdir -p /var/log/caddy

# add Caddyfile if it doesn't exist
if [ ! -f "/etc/caddy/Caddyfile" ]; then
  sudo bash -c 'echo "http://localhost {
  root /srv/www/localhost
}" >> /etc/caddy/Caddyfile'
fi

# add a default page to serve if it doesn't exist
if [ ! -f "/srv/www/localhost/index.html" ]; then
  sudo bash -c 'echo "Welcome to Caddy" >> /srv/www/localhost/index.html'
fi

# change the permissions
sudo chown -R root:www-data /usr/local/bin/caddy
sudo chown -R root:www-data /etc/caddy
sudo chown -R www-data:www-data /etc/ssl/caddy
sudo chown -R www-data:www-data /var/log/caddy
sudo chown -R www-data:www-data /srv/www/localhost
sudo chown root:www-data /etc/systemd/system/caddy.service
sudo chown root:www-data /etc/tmpfiles.d/caddy.conf

sudo chmod 0755 /usr/local/bin/caddy
sudo chmod 0755 /etc/caddy/
sudo chmod 0644 /etc/caddy/Caddyfile
sudo chmod 0770 /etc/ssl/caddy
sudo chmod 0755 /var/log/Caddy
sudo chmod 0775 /srv/www/
sudo chown 0644 /etc/systemd/system/caddy.service
sudo chown 0644 /etc/tmpfiles.d/caddy.conf
```

## Undestanding sytemd and caddy

Read the man page for systemd at <https://www.freedesktop.org/software/systemd/man/systemd.exec.html>

Follow some of the discussion for this systemd service at <https://github.com/mholt/caddy/pull/1566/files>

## Troubleshooting

You can run your caddy configuration in the foreground like so:

```bash
sudo --user=www-data CADDYPATH=/etc/ssl/caddy /usr/local/bin/caddy -log stdout -agree=true -conf=/etc/caddy/Caddyfile -root=/var/tmp
```

### Working with systemd v229 and earlier

You may need to comment out this section of `caddy.service`:

```systemd
# Place a semicolon in front of these lines like so
; CapabilityBoundingSet=CAP_NET_BIND_SERVICE
; AmbientCapabilities=CAP_NET_BIND_SERVICE
; NoNewPrivileges=true
```

### Working with the upload feature

You may need to comment the lines shown above these lines and uncomment these:

```
# Comment the section right above this section and uncomment this one
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_LEASE
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_LEASE
NoNewPrivileges=true
```

Give the caddy binary the ability to bind to privileged ports (e.g. 80, 443) as a non-root user:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
```

## caddy command not found

```bash
sudo cp /path/to/caddy /usr/local/bin
sudo chown root:root /usr/local/bin/caddy
sudo chmod 755 /usr/local/bin/caddy
```

### no user or group www-data

Set up the user, group, and directories that will be needed:

```bash
sudo groupadd -g 33 www-data
sudo useradd \
  -g www-data --no-user-group \
  --home-dir /srv/www --no-create-home \
  --shell /usr/sbin/nologin \
  --system --uid 33 www-data
```

### no Caddyfile

Place your caddy configuration file ("Caddyfile") in the proper directory
and give it appropriate ownership and permissions:

```bash
sudo cp /path/to/Caddyfile /etc/caddy/
sudo chown www-data:www-data /etc/caddy/Caddyfile
sudo chmod 444 /etc/caddy/Caddyfile
```

### no webserver directory

Create the home directory for the server and give it appropriate ownership
and permissions:

```bash
sudo mkdir /srv/www
sudo chown www-data:www-data /srv/www
sudo chmod 775 /srv/www
```

### how to setup a website

Let's assume you have the contents of your website in a directory called 'example.com'.
Put your website into place for it to be served by caddy:

```bash
sudo cp -R example.com /srv/www/
sudo chown -R www-data:www-data /srv/www/example.com
sudo chmod -R 555 /srv/www/example.com
```

You'll need to explicitly configure caddy to serve the site from this location by adding
the following to your Caddyfile if you haven't already:

```
example.com {
    root /srv/www/example.com
    ...
}
```

### Using file system ACLs

You can make other certificates and private key files accessible to the `www-data` user with the following command:

```bash
setfacl -m user:www-data:r-- /etc/ssl/private/my.key
```
