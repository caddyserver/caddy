# systemd unit for caddy

Please do not hesitate to ask on
[caddyserver/support](https://gitter.im/caddyserver/support)
if you have any questions.
Feel free to prepend to your question the username of whoever touched the file most recently,
for example `@wmark re systemd: …`.

The provided file is written for **systemd version 229** or later!

## Quickstart

In the following sections, we will assume that you want to run caddy
as user `www-data` and group `www-data`, with UID and GID 33.
Adjust this to your liking according to the preferences of your Linux distribution!

```bash
groupadd -g 33 www-data
useradd \
  -g www-data --no-user-group \
  --home-dir /var/www --no-create-home \
  --shell /usr/sbin/nologin \
  --system --uid 33 www-data

mkdir /etc/caddy
chown -R root:www-data /etc/caddy
mkdir /etc/ssl/caddy
chown -R www-data:root /etc/ssl/caddy
chmod 0770 /etc/ssl/caddy
```

- Install the unit configuration file: `cp caddy.service /etc/systemd/system/`
- Reload the systemd daemon: `systemctl daemon-reload`
- Make sure to [configure](#configuration) the service unit before starting caddy.
- Start caddy: `systemctl start caddy.service`
- Enable the service (automatically start on boot): `systemctl enable caddy.service`
- A folder `.caddy` will be created inside the home directory of the user that runs caddy;
  you can change that by providing an environment variable `HOME`,
  i.e. `Environment=HOME=/var/lib/caddy` will result in `/var/lib/caddy/.caddy`

## Configuration

- Prefer `systemctl edit` over modifying the unit file directly:
    - `systemctl edit caddy.service` to make user-local modifications
    - `systemctl edit --full caddy.service` for system-wide ones
- In most cases it is enough to override arguments in the `ExecStart` directive:

```ini
[Service]
; an empty value clears the original (and preceding) settings
ExecStart=
ExecStart=/usr/local/bin/caddy -conf="/etc/caddy/myCaddy.conf"
```

- To view the resulting configuration use `systemctl cat caddy`
- systemd needs absolute paths, therefore make sure that the path to caddy is correct.
- Double check permissions of your *document root* path.
  The user caddy runs as needs to have access to it. For example:

```bash
# caddy would run as        www-data:www-data
# serving, in this example: /var/www

sudo -u www-data -g www-data -s \
  ls -hlAS /var/www

# Got an error? Revisit permissions!
```

## Tips

- Use `log stdout` and `errors stderr` in your Caddyfile to fully utilize **journald**.
- `journalctl` is *journald's* log query tool.
- Did caddy not start? Check the logfiles for any error messages using `journalctl --boot -u caddy.service`
- To follow caddy's log output: `journalctl -f -u caddy.service`
- If your GNU/Linux distribution does not use *systemd* with *journald* then check any logfiles in: `/var/log`

- If you have more files that start with `caddy` – like a `caddy.timer`, `caddy.path`, or `caddy.socket` – then it is important to append `.service`.
  Although if `caddy.service` is all you have, then you can just use `caddy` without any extension, such as in: `systemctl status caddy`

- You can make other certificates and private key files accessible to a user `www-data` by command `setfacl`, if you must:

```bash
setfacl -m user:www-data:r-- /etc/ssl/private/my.key
```
